#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "hasher/common.h"
#include "hasher/hashset.h"

#include "hex.h"
#include "hset_decoder.h"
#include "throw.h"
#include "util.h"
#include "hashset/hset.h"
#include "hashset/lookupstrategy.h"
#include "hashset/basic_ls.h"
#include "hashset/block_ls.h"
#include "hashset/block_linear_ls.h"
#include "hashset/radius_ls.h"
#include "hashset/range_ls.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace bip = boost::interprocess;

struct DataHolder {
  DataHolder(void* beg, void* end): beg(beg), end(end) {}

  virtual ~DataHolder() = default;

  void* beg;
  void* end;
};

struct MmapHolder: public DataHolder {
  MmapHolder(const std::filesystem::path& p):
    DataHolder(nullptr, nullptr),
    fm(p.string().c_str(), bip::read_write),
    mr(fm, bip::read_write)
  {
    beg = mr.get_address();
    end = static_cast<char*>(beg) + std::filesystem::file_size(p);
  }

  bip::file_mapping fm;
  bip::mapped_region mr;
};

struct MemoryHolder: public DataHolder {
  MemoryHolder(std::vector<char>&& buf):
    DataHolder(buf.data(), buf.data() + buf.size()),
    buf(buf)
  {}

  std::vector<char> buf;
};

MemoryHolder read_file(const std::filesystem::path& p) {
  const size_t fsize = std::filesystem::file_size(p);

  std::ifstream in(p, std::ios::binary);
  in.exceptions(in.failbit);

  std::vector<char> buf(fsize);
  in.read(buf.data(), fsize);

  return MemoryHolder(std::move(buf));
}

auto load_hset(void* beg, void* end) {
  SFHASH_Error* err = nullptr;

  auto hs = make_unique_del(
    sfhash_load_hashset(beg, end, &err),
    sfhash_destroy_hashset
  );

  THROW_IF(err, err->message);
  THROW_IF(!hs, "!hs");

  return hs;
}

template <class V>
bool lookup_func(const V& hashes, const LookupStrategy& ls) {
  bool r = false;
  for (const auto& h: hashes) {
    // XOR is sensitive to all inputs, so cannot be optimized out
    r ^= ls.contains(h.data());
  }
  return r;
}

template <class HashContainer>
void do_check(const std::string& name, const LookupStrategy& ls, const HashContainer& hashes) {
  const std::string tag = std::to_string(hashes[0].size()) + " x " + std::to_string(hashes.size());

  BENCHMARK(tag + " " + name) {
    return lookup_func(hashes, ls);
  };
}

struct RNG {
  std::mt19937 re;
  std::uniform_int_distribution<uint32_t> dist;

  RNG() {
    std::random_device rd;
    re.seed(rd());
  }

  uint32_t operator()() {
    return dist(re);
  }
};

template <size_t HashLength>
auto make_random_hashes(RNG& rng, size_t count) {
  std::vector<std::array<uint8_t, HashLength>> hashes(count);

  for (auto& h: hashes) {
    // there should be a better way to do this; relies on all hash lengths
    // being multiples of 4
    for (int i = 0; i < static_cast<int>(HashLength / sizeof(uint32_t)); ++i) {
      *reinterpret_cast<uint32_t*>(&h[i*sizeof(uint32_t)]) = rng();
    }
  }

  return hashes;
}

template <size_t HashLength>
auto make_radius_hsd(const ConstHashsetData& hsd, uint32_t radius) {
  return std::unique_ptr<LookupStrategy>{
    std::make_unique<RadiusLookupStrategy<HashLength>>(
      hsd.beg,
      hsd.end,
      radius
    )
  };
}

template <size_t HashLength>
auto make_std_hsd(const ConstHashsetData& hsd) {
  return std::unique_ptr<LookupStrategy>{
    std::make_unique<BasicLookupStrategy<HashLength>>(
      hsd.beg,
      hsd.end
    )
  };
}

template <size_t HashLength>
auto make_two_sided_radius_hsd(const ConstHashsetData& hsd, int64_t left, int64_t right) {
  return std::unique_ptr<LookupStrategy>{
    std::make_unique<RangeLookupStrategy<HashLength>>(
      hsd.beg,
      hsd.end,
      left,
      right
    )
  };
}

template <
  size_t HashLength,
  size_t BucketBits,
  class Blocks
>
auto make_block_radius_hsd(const ConstHashsetData& hsd, Blocks blocks) {
  return std::unique_ptr<LookupStrategy>{
    std::make_unique<BlockLookupStrategy<HashLength, BucketBits>>(
      hsd.beg,
      hsd.end,
      blocks
    )
  };
}

template <
  size_t HashLength,
  size_t BucketBits,
  class Blocks
>
auto make_block_linear_hsd(const ConstHashsetData& hsd, Blocks blocks) {
  return std::unique_ptr<LookupStrategy>{
    std::make_unique<BlockLinearLookupStrategy<HashLength, BucketBits>>(
      hsd.beg,
      hsd.end,
      blocks
    )
  };
}

template <
  class HashGenerator,
  class SetList
>
void do_some_lookups(HashGenerator& gen, const SetList& sets) {
  for (size_t i = 1; i <= 100000; i *= 10) {
    do_some_lookups(gen(i), sets);
  }
}

template <
  class LookupList,
  class SetList
>
void do_some_lookups(const LookupList& ll, const SetList& sets) {
  for (const auto& [name, hs]: sets) {
    do_check(name, *hs, ll);
  }
}

template <size_t HashLength>
std::pair<int64_t, int64_t> make_left_right(const ConstHashsetData& hsd) {

  const uint8_t* const beg = static_cast<const uint8_t*>(hsd.beg);
  const uint8_t* const end = static_cast<const uint8_t*>(hsd.end);

  const std::array<uint8_t, HashLength>* hh = reinterpret_cast<const std::array<uint8_t, HashLength>*>(beg);

  const size_t count = (end - beg) / HashLength;

  int64_t left = std::numeric_limits<int64_t>::max(),
          right = std::numeric_limits<int64_t>::min();

  for (size_t i = 0; i < count; ++i) {
    const size_t e = expected_index(hh[i].data(), count);
    const int64_t delta = static_cast<int64_t>(e) - static_cast<int64_t>(i);

    left = std::min(left, delta);
    right = std::max(right, delta);
  }

  return { left, right };
}

const std::filesystem::path VS{"/home/juckelman/projects/hashsets/src/virusshare/vs-445.hset"};
const std::filesystem::path NSRL{"/home/juckelman/projects/hashsets/src/nsrl/rds-2.78/nsrl-rds-2.78.hset"};

std::array<std::tuple<double, double, double, double>, 8> make_linear() {
  return std::array<std::tuple<double, double, double, double>, 8> {
    std::make_tuple(
      1193.88763743939 + 1800, -0.000644969328527935,
      1193.88763743939 - 2000, -0.000644969328527935
    ),
    std::make_tuple(
      -3716.08775230379 + 1500, -0.000309682721874173,
      -3716.08775230379 - 1500, -0.000309682721874173
    ),
    std::make_tuple(
      -13474.4499500540 + 2600, 0.000173121434859497,
      -13474.4499500540 - 2300, 0.000173121434859497
    ),
    std::make_tuple(
      -9317.58469445582 + 1700, 0.000106712798053326,
      -9317.58469445582 - 1600, 0.000106712798053326
    ),
    std::make_tuple(
      -520.117837030724 + 1500, -0.000118529066484211,
      -520.117837030724 - 1500, -0.000118529066484211
    ),
    std::make_tuple(
      6333.35311611681 + 2200, -0.000223693482308163,
      6333.35311611681 - 2500, -0.000223693482308163
    ),
    std::make_tuple(
      -12744.7868642145 + 1800, 0.000088634456540151,
      -14800, 0.000088634456540151
    ),
    std::make_tuple(
      -42000, 0.0005539,
      -46500, 0.0005539
    )
  };
}

template <
  size_t HashLength,
  size_t BucketBits
>
std::array<std::pair<ssize_t, ssize_t>, (1 << BucketBits)> make_buckets(const ConstHashsetData& hsd) {
  const uint8_t* const beg = static_cast<const uint8_t*>(hsd.beg);
  const uint8_t* const end = static_cast<const uint8_t*>(hsd.end);

  const std::array<uint8_t, HashLength>* hh = reinterpret_cast<const std::array<uint8_t, HashLength>*>(beg);

  const size_t count = (end - beg) / HashLength;

  std::array<std::pair<ssize_t, ssize_t>, (1 << BucketBits)> block_bounds;
  std::fill(
    block_bounds.begin(),
    block_bounds.end(),
    std::make_pair(
      std::numeric_limits<ssize_t>::max(),
      std::numeric_limits<ssize_t>::min()
    )
  );

  for (size_t i = 0; i < count; ++i) {
    const size_t e = expected_index(hh[i].data(), count);
    const ssize_t delta = static_cast<ssize_t>(e) - static_cast<ssize_t>(i);

    const size_t bi = hh[i][0] >> (8 - BucketBits);
    block_bounds[bi].first = std::min(block_bounds[bi].first, delta);
    block_bounds[bi].second = std::max(block_bounds[bi].second, delta);
  }

/*
  for (size_t b = 0; b < block_bounds.size(); ++b) {
    std::cout << b << ' ' << block_bounds[b].first << ' ' << block_bounds[b].second << ' ' << (block_bounds[b].second - block_bounds[b].first) << '\n';
  }
  std::cout << '\n';
*/

  return block_bounds;
}

template <
  size_t HashLength,
  SFHASH_HashAlgorithm HType
>
void do_bench(const std::filesystem::path & p) {
  MmapHolder h(p);

  auto hset = load_hset(h.beg, h.end);

  REQUIRE(sfhash_hash_length(HType) == HashLength);

  const int hidx = sfhash_hashset_index_for_type(hset.get(), HType);
  REQUIRE(hidx != -1);

  auto hsd = std::get<2>(hset->holder.hsets[hidx]);

  RNG rng;
  auto gen = [&rng](size_t count) { return make_random_hashes<HashLength>(rng, count); };

  const auto [left, right] = make_left_right<HashLength>(hsd);
  const auto radius = std::max(std::abs(left), std::abs(right));

  const auto bucket1 = make_buckets<HashLength, 1>(hsd);
  const auto bucket2 = make_buckets<HashLength, 2>(hsd);
  const auto bucket3 = make_buckets<HashLength, 3>(hsd);
  const auto bucket4 = make_buckets<HashLength, 4>(hsd);
  const auto bucket5 = make_buckets<HashLength, 5>(hsd);
  const auto bucket6 = make_buckets<HashLength, 6>(hsd);
  const auto bucket7 = make_buckets<HashLength, 7>(hsd);
  const auto bucket8 = make_buckets<HashLength, 8>(hsd);

  const auto linear8 = make_linear();

  std::vector<std::pair<std::string, std::unique_ptr<LookupStrategy>>> sets;
  sets.emplace_back("radius", make_radius_hsd<HashLength>(hsd, radius));
  sets.emplace_back("2radius", make_two_sided_radius_hsd<HashLength>(hsd, left, right));
  sets.emplace_back("bradius2", make_block_radius_hsd<HashLength, 1>(hsd, bucket1));
  sets.emplace_back("bradius4", make_block_radius_hsd<HashLength, 2>(hsd, bucket2));
  sets.emplace_back("bradius8", make_block_radius_hsd<HashLength, 3>(hsd, bucket3));
  sets.emplace_back("bradius16", make_block_radius_hsd<HashLength, 4>(hsd, bucket4));
  sets.emplace_back("bradius32", make_block_radius_hsd<HashLength, 5>(hsd, bucket5));
  sets.emplace_back("bradius64", make_block_radius_hsd<HashLength, 6>(hsd, bucket6));
  sets.emplace_back("bradius128", make_block_radius_hsd<HashLength, 7>(hsd, bucket7));
  sets.emplace_back("bradius256", make_block_radius_hsd<HashLength, 8>(hsd, bucket8));
//  sets.emplace_back("blinear8", make_block_linear_hsd<HashLength, 3>(hsd, linear8));
  sets.emplace_back("std", make_std_hsd<HashLength>(hsd));

  do_some_lookups(gen, sets);
}

TEST_CASE("MmapLookupBenchVS") {
  do_bench<16, SFHASH_MD5>(VS);
}

TEST_CASE("MmapLookupBenchNSRL") {
  do_bench<20, SFHASH_SHA_1>(NSRL);
}

/*
TEST_CASE("xxxxx") {
  const std::vector<std::array<uint8_t, 20>> test1_in{
    to_bytes<20>("03056bc08003a879889005a316b5f9159b1cba5a"),
    to_bytes<20>("04d4b13b2cf44056a14a1550640492a907469e9e"),
    to_bytes<20>("071845537205a14ce14d6e05754ccaacd77985a5"),
    to_bytes<20>("0d22700a42104d981f62b3c81a29f2fc4bdac4db"),
    to_bytes<20>("107573c2f4809bbf0b46570063362a8ab4082a80"),
    to_bytes<20>("10cb8e2d8b8c4ec01af5d04efc21908ee24eedd6"),
    to_bytes<20>("12361014ba6cb7dc695c523c8c13cbff5cfbbe38"),
    to_bytes<20>("12a4898b9c77c746c4cc1661706597975b43fa0d"),
    to_bytes<20>("14ca1c6af0e0e43f8c4b40bc5bbd236aab4c5ea7"),
    to_bytes<20>("1ed6c5b149b19bb08c1402bf11be2ce9ce772e07"),
    to_bytes<20>("2028bffadfd9b989bcc63da90596101fe4ec20b9"),
    to_bytes<20>("217e04a768f3c9407fcc1cca1838651e6aa02326"),
    to_bytes<20>("286ba1181663193d119d7ca18331395cd451de91"),
    to_bytes<20>("28b64738d918471b4a726e4f25ba7a7b10adf525"),
    to_bytes<20>("28f38343315a5a158a5468f43d45d0c6962b291f"),
    to_bytes<20>("2d5bb43574ef4d1a6152a001f23bef6cbdafc795"),
    to_bytes<20>("2dce6c6bd297abfa1716603d0556ef0d4d3dc0fa"),
    to_bytes<20>("2f3ca0b9eecd7b6bb806d49b0f7cbd46b20c66b5"),
    to_bytes<20>("30672cb00291bfa040828e9e49040717be84acf2"),
    to_bytes<20>("3156aaf7d2b5f57ad19798ef2cd54aa94a7719b1"),
    to_bytes<20>("35bef7b69613c047060c8c3a374c7c950b310ed0"),
    to_bytes<20>("37f8839889b9042a7d30f986f4001770bd6a2ee5"),
    to_bytes<20>("3aae847c163fa6cc7c8241a3a49f98705538d55f"),
    to_bytes<20>("3b130f464fabf3a0a785f37c637707ad1da139e9"),
    to_bytes<20>("43022ebb4a6f3f867c6a4b4f5bb67e9dacb4f207"),
    to_bytes<20>("4596ee83c7c8a803e64b87c2e9603e070e8d5b3e"),
    to_bytes<20>("49de15b0b89c615cb91a312dc120d015a23fbf21"),
    to_bytes<20>("4c83c16db2d4450a08982cbfc65ae040f1ee4dbe"),
    to_bytes<20>("5121ca6fcb17b191f2f9a806510ca5adc75bb606"),
    to_bytes<20>("513082a28f409969550fcd9e0685512bc08ffdc6"),
    to_bytes<20>("518c9381f46d97f2e3402e2f954f03b94af8a2b4"),
    to_bytes<20>("52f4fa1709f95c4def8db07224cdae72916f9f92"),
    to_bytes<20>("5467feff61dde7a37428a613197cf39d6d3fb34d"),
    to_bytes<20>("55250d55d5bb84d127e34bde24ea32d86a4d1584"),
    to_bytes<20>("59d6050848b6025666f1e8854694736259da49b2"),
    to_bytes<20>("5aaca1af104df827870140817e920946b492d51a"),
    to_bytes<20>("5f0a89da047b9ec48975bb5ccd66631c919b5738"),
    to_bytes<20>("5f683a7f2a8aef27a3d34bbeb0eff006ce07871f"),
    to_bytes<20>("61a405778b497ff90ea8a554440733a00f35ae51"),
    to_bytes<20>("62d4e3056e772a5f2912c89a119ae8aa26625499"),
    to_bytes<20>("64a73675f1574c38015e3c4c0822d750362de995"),
    to_bytes<20>("6871957156b07ae46e5f75da9510a56c79b45c76"),
    to_bytes<20>("704239535a35062c45ecad41a6f95649f6bb806f"),
    to_bytes<20>("70c9696dc9ff62187f67147bd2c6d875f0318993"),
    to_bytes<20>("74bf89f63e5a0743e26d1dd0fd3199e719034079"),
    to_bytes<20>("7d69abfd75a2e89aba37e9eb404fa5aea3d7a6f8"),
    to_bytes<20>("8926519e4c57579b7a02dbab9486c80e6ba5b328"),
    to_bytes<20>("8ac460a2237ce354ac1bd6815d697b3827f0a2ff"),
    to_bytes<20>("92952baf4a0e0ac41170b3138924a72dbeef0983"),
    to_bytes<20>("983f40b44129915538e7764ce4f550f3a010caa8"),
    to_bytes<20>("9939741d31d8975deecd53271415a58af66b2f11"),
    to_bytes<20>("9a2834df62ca06ee0a14d96449a4d0c394d04642"),
    to_bytes<20>("9bd8e3294486abffa3974e4ac2d040937a80f604"),
    to_bytes<20>("9bf0d513e6354e69935a000d98f374003fac2023"),
    to_bytes<20>("9c670bf837c593f328a5e864f4ae432d466f950d"),
    to_bytes<20>("9cd35d79da7776af14f21b259c64f130fa1a3536"),
    to_bytes<20>("9cf7b0d5187a61d2474f33fec1fe18cc5cb5919f"),
    to_bytes<20>("a1d9e2d650c991847adfd2444f2a09ea16754987"),
    to_bytes<20>("a3fa154e89ed75569b34e5356a4bc7857caabf00"),
    to_bytes<20>("ab788a5507837d9afbfa0f571f6524edaf185447"),
    to_bytes<20>("ad4909b3b9f0b1acc425ff631365aaac5e0c6181"),
    to_bytes<20>("ae37641b7ddb9dcff7ece9bd4a3ae7409d47b781"),
    to_bytes<20>("b050c35601ef94b69e903c60433e0f098905bb19"),
    to_bytes<20>("b2cfa66b7ada0f602ac2bcd33aae3ef0c6af746a"),
    to_bytes<20>("b2d60331966591168cfbb151f8377e63891e87c1"),
    to_bytes<20>("b536fc03676b226b0b09154544b97f88a155eea9"),
    to_bytes<20>("bbc2c7adf9a9dc6087f2ad40722fdce7037f1651"),
    to_bytes<20>("bd9d05ec2cf0cecda46e6837b7d6f7dbac79ae69"),
    to_bytes<20>("c0593c7348f3083484d8e3d708a1871febe26659"),
    to_bytes<20>("c2eb79e407b853966a4e0b0c016b6fe08f565c5c"),
    to_bytes<20>("c3a331125c2f594cf131dc00fd9f4340e194c0e5"),
    to_bytes<20>("c9aaefa49129d2d1240f0d66362fe51dc722a680"),
    to_bytes<20>("c9fcde4c72df876ea7586e2b49e20c15a3724899"),
    to_bytes<20>("cc45d942931a98da3da4d690de1ed1d2063284ca"),
    to_bytes<20>("cd177ebdc23c7798852e6beb6c53072e435545f8"),
    to_bytes<20>("ce3ceb88c211dffa6788113a3b43ef6624db293c"),
    to_bytes<20>("cfbe0007014a5a2cff96b0929664c174e3fc06c1"),
    to_bytes<20>("d10e1971a4155fe0caafb60e022ec6687bee4ba3"),
    to_bytes<20>("db95884ed933a5c3e40f788c55d928f18e2a842f"),
    to_bytes<20>("de18e464da943e8b69b3f84ecbfd6cdb28b996de"),
    to_bytes<20>("df7c40b52a03b081387be031c01c5b4a0fffd1af"),
    to_bytes<20>("dfe6bd41723efa523ab700b5f6e8451b954bf81a"),
    to_bytes<20>("e21f085615f98d3751690c1615923e89160d5783"),
    to_bytes<20>("e3cc51c54197fdcd477a73e7f8a0b6b55eaa8478"),
    to_bytes<20>("e3ddc110e667da2893df8ea3f60b2d2131e075f0"),
    to_bytes<20>("e4ae099d7eba7990167adea3342b84bb9b547e5f"),
    to_bytes<20>("e57a476cce72c8cdb014c8474db21c40df4e8151"),
    to_bytes<20>("ec05c2999ecf1bee1703136614b2105eb8d02cfe"),
    to_bytes<20>("ed5a07bd2a8f19927d53270daf294cf72de099b6"),
    to_bytes<20>("f0b7c7852b0ac6d9bbdee6b0efca1907ccea1b43"),
    to_bytes<20>("f4d63dcd3df553fbb32eae4b2f52ab8ebf1827a7"),
    to_bytes<20>("f612e2226b9a75ad6f70639446ab252e006fe6f7"),
    to_bytes<20>("f731f25127744a1d340fd061b16dbd241051acb8"),
    to_bytes<20>("f85a7e62b84e0400c0f0e69017187b63c05a4570"),
    to_bytes<20>("f9b4e1f0912b51096e60e51affa4b8ee9582add8"),
    to_bytes<20>("f9eac6121a7f4bd117f0953e2f9f691b0db307fa"),
    to_bytes<20>("fa54091007e91cd14ba99e42c03b72defbfd9043"),
    to_bytes<20>("fc4508e84ff605ef872d9eab553d8d63f27cd68a"),
    to_bytes<20>("fc79cd2c2685a0fe0ca178a41de6c7d7830e98ca"),
    to_bytes<20>("fc824043658c86424b5f2d480134dce7b004143d")
  };

  MmapHolder h(NSRL);
  const size_t HashLength = 20;

  auto hset = load_hset(h.beg, h.end);

  const auto htype = SFHASH_SHA_1;
  REQUIRE(sfhash_hash_length(htype) == HashLength);

  const int hidx = sfhash_hashset_index_for_type(hset.get(), htype);
  REQUIRE(hidx != -1);

  auto hsd = std::get<2>(hset->holder.hsets[hidx]);

  const auto [left, right] = make_left_right<HashLength>(hsd);
  const auto radius = std::max(std::abs(left), std::abs(right));

  std::cout << left << ' ' << right << '\n';
/*
  const auto bucket1 = make_buckets<HashLength, 1>(h);
  const auto bucket2 = make_buckets<HashLength, 2>(h);
  const auto bucket3 = make_buckets<HashLength, 3>(h);
  const auto bucket4 = make_buckets<HashLength, 4>(h);
  const auto bucket5 = make_buckets<HashLength, 5>(h);
  const auto bucket6 = make_buckets<HashLength, 6>(h);
  const auto bucket7 = make_buckets<HashLength, 7>(h);
  const auto bucket8 = make_buckets<HashLength, 8>(h);

  const auto linear8 = make_linear();
*/

  std::cout << radius << '\n';

  std::vector<std::pair<std::string, std::unique_ptr<LookupStrategy>>> sets;
  sets.emplace_back("std", make_std_hsd<HashLength>(hsd));
  sets.emplace_back("radius", make_radius_hsd<HashLength>(hsd, radius));
  sets.emplace_back("2radius", make_two_sided_radius_hsd<HashLength>(hsd, left, right));
/*
  sets.emplace_back("bradius2", make_block_radius_hsd<HashLength, 1>(h, *hsinfo, bucket1));
  sets.emplace_back("bradius4", make_block_radius_hsd<HashLength, 2>(h, *hsinfo, bucket2));
  sets.emplace_back("bradius8", make_block_radius_hsd<HashLength, 3>(h, *hsinfo, bucket3));
  sets.emplace_back("bradius16", make_block_radius_hsd<HashLength, 4>(h, *hsinfo, bucket4));
  sets.emplace_back("bradius32", make_block_radius_hsd<HashLength, 5>(h, *hsinfo, bucket5));
  sets.emplace_back("bradius64", make_block_radius_hsd<HashLength, 6>(h, *hsinfo, bucket6));
  sets.emplace_back("bradius128", make_block_radius_hsd<HashLength, 7>(h, *hsinfo, bucket7));
  sets.emplace_back("bradius256", make_block_radius_hsd<HashLength, 8>(h, *hsinfo, bucket8));
//  sets.emplace_back("blinear8", make_block_linear_hsd<HashLength, 3>(h, *hsinfo, linear8));
*/

  std::vector<bool> hits(sets.size());

  for (const auto& h: test1_in) {
    for (size_t i = 0; i < sets.size(); ++i) {
      hits[i] = sets[i].second->contains(h.data());
      std::cout << hits[i];
    }
    std::cout << '\n';

//    CHECK(std::find(hits.begin() + 1, hits.end(), !hits[0]) == hits.end());
  }
}
