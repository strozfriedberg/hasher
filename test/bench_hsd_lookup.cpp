#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <ostream>
#include <random>
#include <string>
#include <sstream>
#include <vector>

#include "hasher/api.h"

#include "hashsetdata.h"
#include "hashsetinfo.h"
#include "hex.h"
#include "throw.h"
#include "util.h"

#include "hsd_impls/basic_hsd.h"
#include "hsd_impls/block_hsd.h"
#include "hsd_impls/hsd_utils.h"
#include "hsd_impls/radius_hsd.h"
#include "hsd_impls/range_hsd.h"

const std::filesystem::path VS{"test/virusshare-389.hset"};
const size_t VS_HLEN = 16;

const std::filesystem::path NSRL{"test/nsrl_rds_2.71_asdf_hashes.hset"};
const size_t NSRL_HLEN = 20;

// interface for the raw hashset data
struct Holder {
  virtual ~Holder() = default;

  void* beg;
  void* end;
};

// holds raw hashset data in memory
struct MemoryHolder: public Holder {
  MemoryHolder(std::vector<char>&& the_buf): buf(std::move(the_buf)) {
    beg = buf.data();
    end = buf.data() + buf.size();
  }

  std::vector<char> buf;
};

// read a file into memory
MemoryHolder read_file(const std::filesystem::path& p) {
  const size_t fsize = std::filesystem::file_size(p);

  std::ifstream in(p, std::ios::binary);
  in.exceptions(in.failbit);

  std::vector<char> buf(fsize);
  in.read(buf.data(), fsize);

  return MemoryHolder(std::move(buf));
}

// get the hashset header
auto load_header(void *beg, void* end) {
  SFHASH_Error* err = nullptr;

  auto hsinfo = make_unique_del(
    sfhash_load_hashset_info(beg, end, &err),
    sfhash_destroy_hashset_info
  );

  THROW_IF(err, err->message);
  THROW_IF(!hsinfo, "!hsinfo");

  return hsinfo;
}

struct RNG {
  std::mt19937 re{std::random_device{}()};
  std::uniform_int_distribution<uint32_t> dist;

  uint32_t operator()() {
    return dist(re);
  }
};

// generate some random hashes
template <
  size_t HashLength
>
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

// sample some hashes from hashset data
template <
  size_t HashLength,
  class Generator,
  class Holder
>
auto sample_hashes(Generator& gen, const Holder& h, size_t count) {
  std::vector<std::array<uint8_t, HashLength>> hashes;
  std::sample(
    static_cast<const std::array<uint8_t, HashLength>*>(h.beg),
    static_cast<const std::array<uint8_t, HashLength>*>(h.end),
    std::back_inserter(hashes),
    count,
    gen
  );
  return hashes;
}

// make a HashSetDataImpl from hashset data 
template <
  size_t HashLength,
  class Holder
>
auto make_basic_hsd(Holder& h, const SFHASH_HashSetInfo& hsinfo) {
  return std::unique_ptr<HashSetData>{
    std::make_unique<BasicHashSetDataImpl<HashLength>>(
      static_cast<const char*>(h.beg) + hsinfo.hashset_off,
      static_cast<const char*>(h.beg) + hsinfo.hashset_off + hsinfo.hashset_size * hsinfo.hash_length
    )
  };
}

// make a RadiusHashSetDataImpl from hashset data
template <
  size_t HashLength,
  class Holder
>
auto make_radius_hsd(Holder& h, const SFHASH_HashSetInfo& hsinfo) {
  return std::unique_ptr<HashSetData>{
    std::make_unique<RadiusHashSetDataImpl<HashLength>>(
      static_cast<const char*>(h.beg) + hsinfo.hashset_off,
      static_cast<const char*>(h.beg) + hsinfo.hashset_off + hsinfo.hashset_size * hsinfo.hash_length,
      hsinfo.radius
    )
  };
}

template <
  size_t HashLength,
  class Holder
>
auto make_range_hsd(Holder& h, const SFHASH_HashSetInfo& hsinfo, int64_t left, int64_t right) {
  return std::unique_ptr<HashSetData>{
    std::make_unique<RangeHashSetDataImpl<HashLength>>(
      static_cast<const char*>(h.beg) + hsinfo.hashset_off,
      static_cast<const char*>(h.beg) + hsinfo.hashset_off + hsinfo.hashset_size * hsinfo.hash_length,
      left,
      right
    )
  };
}

template <
  size_t HashLength,
  size_t BlockBits,
  class Holder,
  class Blocks
>
auto make_block_hsd(Holder& h, const SFHASH_HashSetInfo& hsinfo, Blocks blocks) {
  return std::unique_ptr<HashSetData>{
    std::make_unique<BlockHashSetDataImpl<HashLength, BlockBits>>(
      static_cast<const char*>(h.beg) + hsinfo.hashset_off,
      static_cast<const char*>(h.beg) + hsinfo.hashset_off + hsinfo.hashset_size * hsinfo.hash_length,
      blocks
    )
  };
}

template <
  class LookupList
>
bool lookup_func(const HashSetData& hsd, const LookupList& hashes) {
  bool r = false;
  for (const auto& h: hashes) {
    // XOR is sensitive to all inputs, so cannot be optimized out
    r ^= hsd.contains(h.data());
  }
  return r;
}

template <
  class LookupList
>
void do_check(const std::string& name, const HashSetData& hsd, const LookupList& hashes) {
  const std::string tag = std::to_string(hashes[0].size()) + " x " + std::to_string(hashes.size());

  BENCHMARK(tag + " " + name) {
    return lookup_func(hsd, hashes);
  };
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

template <
  class HashGenerator,
  class SetList
>
void do_some_lookups(HashGenerator& gen, const SetList& sets, size_t min, size_t max, size_t mult) {
  for (size_t i = min; i <= max; i *= mult) {
    do_some_lookups(gen(i), sets);
  }
}

template <
  size_t HashLength,
  class Holder,
  class SetList
>
void do_benchmark(const Holder& h, const SetList& hsds) {
  RNG rng;
  auto gen = [&rng](size_t count) {
    return make_random_hashes<HashLength>(rng, count);
  };

  do_some_lookups(gen, hsds, 1, 100000, 10);
}

// check that all results for the given hash match
template <
  class Hash
>
bool check_agreement(const Hash& h, const std::vector<bool>& hits, std::ostream& out) {

  const bool ok = std::find(hits.begin() + 1, hits.end(), !hits[0]) == hits.end();
/*
  if (!ok) {
    std::ostringstream ss;
    ss << to_hex(h) << ": ";
    for (auto b: hits) {
      ss << b;
    }
    FAIL(ss.str());
  }
*/

  out << to_hex(h) << ": ";
  for (auto b: hits) {
    out << b;
  }
  out << '\n';

  return ok;
}

template <
  class LookupList,
  class SetList
>
bool check_agreement(const LookupList& lookups, const SetList& hsds, std::ostream& out) {
  bool ok = true;
  std::vector<bool> hits(hsds.size());
  for (const auto& h: lookups) {
    for (size_t i = 0; i < hsds.size(); ++i) {
      hits[i] = hsds[i].second->contains(h.data());
    }
    ok &= check_agreement(h, hits, out);
  }
  return ok;
}

template <
  size_t HashLength,
  class Holder,
  class SetList
>
void do_agreement_check(const Holder& h, const SetList& hsds) {
  // lookup some random hashes
  RNG rng;
  auto gen = [&rng](size_t count) {
    return make_random_hashes<HashLength>(rng, count);
  };

  bool ok = true;
  std::ostringstream ss;

  const auto lookup_random = gen(1000);
  ok &= check_agreement(lookup_random, hsds, ss);

  // lookup some randomly sampled hashes
  const auto lookup_sample = sample_hashes<HashLength>(rng.re, h, 1000);
  ok &= check_agreement(lookup_sample, hsds, ss);

  if (!ok) {
    FAIL(ss.str());
  }
}

template <
  size_t HashLength,
  class Holder
>
std::pair<int64_t, int64_t> make_left_right(Holder& h) {
  const auto hsinfo = load_header(h.beg, h.end);
  REQUIRE(hsinfo->hash_length == HashLength);

  const uint8_t* const beg = static_cast<const uint8_t*>(h.beg) + hsinfo->hashset_off;

  const std::array<uint8_t, HashLength>* hh = reinterpret_cast<const std::array<uint8_t, HashLength>*>(beg);

  int64_t left = std::numeric_limits<int64_t>::max(),
          right = std::numeric_limits<int64_t>::min();

  for (size_t i = 0; i < hsinfo->hashset_size; ++i) {
    const size_t e = expected_index(hh[i].data(), hsinfo->hashset_size);
    const int64_t delta = static_cast<int64_t>(i) - static_cast<int64_t>(e);

    left = std::min(left, delta);
    right = std::max(right, delta);
  }

  return { left, right };
}

template <
  size_t HashLength,
  size_t BlockBits,
  class Holder
>
std::array<std::pair<ssize_t, ssize_t>, (1 << BlockBits)> make_block_bounds(Holder& h) {
  const auto hsinfo = load_header(h.beg, h.end);
  REQUIRE(hsinfo->hash_length == HashLength);

  const uint8_t* const beg = static_cast<const uint8_t*>(h.beg) + hsinfo->hashset_off;

  const std::array<uint8_t, HashLength>* hh = reinterpret_cast<const std::array<uint8_t, HashLength>*>(beg);

  std::array<std::pair<ssize_t, ssize_t>, (1 << BlockBits)> block_bounds;
  std::fill(
    block_bounds.begin(),
    block_bounds.end(),
    std::make_pair(
      std::numeric_limits<ssize_t>::max(),
      std::numeric_limits<ssize_t>::min()
    )
  );

  for (size_t i = 0; i < hsinfo->hashset_size; ++i) {
    const size_t e = expected_index(hh[i].data(), hsinfo->hashset_size);
    const ssize_t delta = static_cast<ssize_t>(i) - static_cast<ssize_t>(e);

    const size_t bi = hh[i][0] >> (8 - BlockBits);
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
  class Holder
>
auto make_hsds(const Holder& h) {
  const auto hsinfo = load_header(h.beg, h.end);
  REQUIRE(hsinfo->hash_length == HashLength);

  const auto [left, right] = make_left_right<HashLength>(h);

  const auto blocks1 = make_block_bounds<HashLength, 1>(h);
  const auto blocks2 = make_block_bounds<HashLength, 2>(h);
  const auto blocks3 = make_block_bounds<HashLength, 3>(h);
  const auto blocks4 = make_block_bounds<HashLength, 4>(h);
  const auto blocks5 = make_block_bounds<HashLength, 5>(h);
  const auto blocks6 = make_block_bounds<HashLength, 6>(h);
  const auto blocks7 = make_block_bounds<HashLength, 7>(h);
  const auto blocks8 = make_block_bounds<HashLength, 8>(h);

  std::vector<std::pair<std::string, std::unique_ptr<HashSetData>>> hsds;
// TODO: why can't these go into an intializer list?
  hsds.emplace_back("basic", make_basic_hsd<HashLength>(h, *hsinfo));
  hsds.emplace_back("radius", make_radius_hsd<HashLength>(h, *hsinfo));
  hsds.emplace_back("range", make_range_hsd<HashLength>(h, *hsinfo, left, right));
  hsds.emplace_back("block2", make_block_hsd<HashLength, 1>(h, *hsinfo, blocks1));
  hsds.emplace_back("block4", make_block_hsd<HashLength, 2>(h, *hsinfo, blocks2));
  hsds.emplace_back("block8", make_block_hsd<HashLength, 3>(h, *hsinfo, blocks3));
  hsds.emplace_back("block16", make_block_hsd<HashLength, 4>(h, *hsinfo, blocks4));
  hsds.emplace_back("block32", make_block_hsd<HashLength, 5>(h, *hsinfo, blocks5));
  hsds.emplace_back("block64", make_block_hsd<HashLength, 6>(h, *hsinfo, blocks6));
  hsds.emplace_back("block128", make_block_hsd<HashLength, 7>(h, *hsinfo, blocks7));
  hsds.emplace_back("block256", make_block_hsd<HashLength, 8>(h, *hsinfo, blocks8));

  return hsds;
}

TEST_CASE("MemoryLookupCheckVirusShare") {
  MemoryHolder h{read_file(VS)};
  const auto hsds = make_hsds<VS_HLEN>(h);
  do_agreement_check<VS_HLEN>(h, hsds);
}

TEST_CASE("MemoryLookupCheckNSRL") {
  MemoryHolder h{read_file(NSRL)};
  const auto hsds = make_hsds<NSRL_HLEN>(h);
  do_agreement_check<NSRL_HLEN>(h, hsds);
}

TEST_CASE("MemoryLookupBenchVirusShare") {
  MemoryHolder h{read_file(VS)};
  const auto hsds = make_hsds<VS_HLEN>(h);
  do_benchmark<VS_HLEN>(h, hsds);
}

TEST_CASE("MemoryLookupBenchNSRL") {
  MemoryHolder h{read_file(NSRL)};
  const auto hsds = make_hsds<NSRL_HLEN>(h);
  do_benchmark<NSRL_HLEN>(h, hsds);
}
