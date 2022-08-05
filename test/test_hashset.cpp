#include "hasher/api.h"

#include "hashsetdata.h"
#include "hashsetinfo.h"
#include "hex.h"
#include "util.h"

/*
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
*/

#include <chrono>
#include <iostream>

#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

using HashSetInfo = SFHASH_HashSetInfo;

bool operator==(const HashSetInfo& l, const HashSetInfo& r) {
  return l.version == r.version &&
         l.hash_type == r.hash_type &&
         l.hash_length == r.hash_length &&
         l.flags == r.flags &&
         l.hashset_size == r.hashset_size &&
         l.hashset_off == r.hashset_off &&
         l.sizes_off == r.sizes_off &&
         l.radius == r.radius &&
         !std::memcmp(l.hashset_sha256, r.hashset_sha256,
                      sizeof(l.hashset_sha256)) &&
         !std::strcmp(l.hashset_name, r.hashset_name) &&
         !std::strcmp(l.hashset_time, r.hashset_time) &&
         !std::strcmp(l.hashset_desc, r.hashset_desc);
}

std::ostream& operator<<(std::ostream& o, const HashSetInfo& h) {
  o << '{'
    << h.version << ','
    << h.hash_type << ","
    << h.hash_length << ','
    << h.flags << ','
    << h.hashset_size << ','
    << h.hashset_off << ','
    << h.sizes_off << ','
    << h.radius << ','
    << to_hex(h.hashset_sha256,
              h.hashset_sha256 + sizeof(h.hashset_sha256)) << ','
    << '"' << h.hashset_name << "\","
    << '"' << h.hashset_time << "\","
    << '"' << h.hashset_desc << "\""
    << '}';
  return o;
}

#include <catch2/catch_test_macros.hpp>

std::vector<char> read_file(const std::string& path) {
  std::ifstream in(path, std::ios_base::binary);
  return std::vector<char>(std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>());
}

char test1_name[] = "Some test hashes";
char test1_timestamp[] = "2020-02-12T11:58:19.910221";
char test1_desc[] = "These are test hashes.";

const HashSetInfo test1_info{
  1,                            // version
  SFHASH_SHA_1,                 // hash type
  20,                           // hash length
  0,                            // flags
  100,                          // hashset size
  4096,                         // hashset offset
  6096,                         // sizes offset
  10,                           // radius
  {
    0x26, 0xad, 0xe2, 0x56, 0xa8, 0xae, 0x8d, 0x63,
    0x07, 0xcf, 0xbd, 0xc2, 0x24, 0xbd, 0xfa, 0x32,
    0x0a, 0xbd, 0xf6, 0x25, 0x9a, 0x69, 0x44, 0x69,
    0x16, 0x13, 0x70, 0x12, 0x37, 0xe7, 0x51, 0xe4
  },                            // hashset SHA256
  test1_name,                   // hashset name
  test1_timestamp,              // hashset timestamp
  test1_desc,                   // hashset description
};

const std::vector<std::pair<std::array<uint8_t, 20>, uint64_t>> test1_in{
  { to_bytes<20>("03056bc08003a879889005a316b5f9159b1cba5a"), 115 },
  { to_bytes<20>("04d4b13b2cf44056a14a1550640492a907469e9e"), 360 },
  { to_bytes<20>("071845537205a14ce14d6e05754ccaacd77985a5"), 181 },
  { to_bytes<20>("0d22700a42104d981f62b3c81a29f2fc4bdac4db"), 212 },
  { to_bytes<20>("107573c2f4809bbf0b46570063362a8ab4082a80"), 500 },
  { to_bytes<20>("10cb8e2d8b8c4ec01af5d04efc21908ee24eedd6"), 205 },
  { to_bytes<20>("12361014ba6cb7dc695c523c8c13cbff5cfbbe38"), 2502 },
  { to_bytes<20>("12a4898b9c77c746c4cc1661706597975b43fa0d"), 289 },
  { to_bytes<20>("14ca1c6af0e0e43f8c4b40bc5bbd236aab4c5ea7"), 434 },
  { to_bytes<20>("1ed6c5b149b19bb08c1402bf11be2ce9ce772e07"), 197 },
  { to_bytes<20>("2028bffadfd9b989bcc63da90596101fe4ec20b9"), 4384 },
  { to_bytes<20>("217e04a768f3c9407fcc1cca1838651e6aa02326"), 23567 },
  { to_bytes<20>("286ba1181663193d119d7ca18331395cd451de91"), 2837 },
  { to_bytes<20>("28b64738d918471b4a726e4f25ba7a7b10adf525"), 269 },
  { to_bytes<20>("28f38343315a5a158a5468f43d45d0c6962b291f"), 373 },
  { to_bytes<20>("2d5bb43574ef4d1a6152a001f23bef6cbdafc795"), 140 },
  { to_bytes<20>("2dce6c6bd297abfa1716603d0556ef0d4d3dc0fa"), 4383 },
  { to_bytes<20>("2f3ca0b9eecd7b6bb806d49b0f7cbd46b20c66b5"), 1293 },
  { to_bytes<20>("30672cb00291bfa040828e9e49040717be84acf2"), 342 },
  { to_bytes<20>("3156aaf7d2b5f57ad19798ef2cd54aa94a7719b1"), 9229 },
  { to_bytes<20>("35bef7b69613c047060c8c3a374c7c950b310ed0"), 371 },
  { to_bytes<20>("37f8839889b9042a7d30f986f4001770bd6a2ee5"), 794 },
  { to_bytes<20>("3aae847c163fa6cc7c8241a3a49f98705538d55f"), 699 },
  { to_bytes<20>("3b130f464fabf3a0a785f37c637707ad1da139e9"), 36527 },
  { to_bytes<20>("43022ebb4a6f3f867c6a4b4f5bb67e9dacb4f207"), 458 },
  { to_bytes<20>("4596ee83c7c8a803e64b87c2e9603e070e8d5b3e"), 1427 },
  { to_bytes<20>("49de15b0b89c615cb91a312dc120d015a23fbf21"), 1376 },
  { to_bytes<20>("4c83c16db2d4450a08982cbfc65ae040f1ee4dbe"), 476 },
  { to_bytes<20>("5121ca6fcb17b191f2f9a806510ca5adc75bb606"), 2889 },
  { to_bytes<20>("513082a28f409969550fcd9e0685512bc08ffdc6"), 13824 },
  { to_bytes<20>("518c9381f46d97f2e3402e2f954f03b94af8a2b4"), 9888 },
  { to_bytes<20>("52f4fa1709f95c4def8db07224cdae72916f9f92"), 1375 },
  { to_bytes<20>("5467feff61dde7a37428a613197cf39d6d3fb34d"), 1497 },
  { to_bytes<20>("55250d55d5bb84d127e34bde24ea32d86a4d1584"), 1356 },
  { to_bytes<20>("59d6050848b6025666f1e8854694736259da49b2"), 172 },
  { to_bytes<20>("5aaca1af104df827870140817e920946b492d51a"), 291 },
  { to_bytes<20>("5f0a89da047b9ec48975bb5ccd66631c919b5738"), 57 },
  { to_bytes<20>("5f683a7f2a8aef27a3d34bbeb0eff006ce07871f"), 342 },
  { to_bytes<20>("61a405778b497ff90ea8a554440733a00f35ae51"), 7382 },
  { to_bytes<20>("62d4e3056e772a5f2912c89a119ae8aa26625499"), 209 },
  { to_bytes<20>("64a73675f1574c38015e3c4c0822d750362de995"), 141 },
  { to_bytes<20>("6871957156b07ae46e5f75da9510a56c79b45c76"), 324089 },
  { to_bytes<20>("704239535a35062c45ecad41a6f95649f6bb806f"), 42 },
  { to_bytes<20>("70c9696dc9ff62187f67147bd2c6d875f0318993"), 6873 },
  { to_bytes<20>("74bf89f63e5a0743e26d1dd0fd3199e719034079"), 4963 },
  { to_bytes<20>("7d69abfd75a2e89aba37e9eb404fa5aea3d7a6f8"), 13771 },
  { to_bytes<20>("8926519e4c57579b7a02dbab9486c80e6ba5b328"), 210 },
  { to_bytes<20>("8ac460a2237ce354ac1bd6815d697b3827f0a2ff"), 638 },
  { to_bytes<20>("92952baf4a0e0ac41170b3138924a72dbeef0983"), 188 },
  { to_bytes<20>("983f40b44129915538e7764ce4f550f3a010caa8"), 344891 },
  { to_bytes<20>("9939741d31d8975deecd53271415a58af66b2f11"), 4641 },
  { to_bytes<20>("9a2834df62ca06ee0a14d96449a4d0c394d04642"), 333 },
  { to_bytes<20>("9bd8e3294486abffa3974e4ac2d040937a80f604"), 3241 },
  { to_bytes<20>("9bf0d513e6354e69935a000d98f374003fac2023"), 388 },
  { to_bytes<20>("9c670bf837c593f328a5e864f4ae432d466f950d"), 3391 },
  { to_bytes<20>("9cd35d79da7776af14f21b259c64f130fa1a3536"), 14514 },
  { to_bytes<20>("9cf7b0d5187a61d2474f33fec1fe18cc5cb5919f"), 4182 },
  { to_bytes<20>("a1d9e2d650c991847adfd2444f2a09ea16754987"), 194 },
  { to_bytes<20>("a3fa154e89ed75569b34e5356a4bc7857caabf00"), 250 },
  { to_bytes<20>("ab788a5507837d9afbfa0f571f6524edaf185447"), 342 },
  { to_bytes<20>("ad4909b3b9f0b1acc425ff631365aaac5e0c6181"), 184 },
  { to_bytes<20>("ae37641b7ddb9dcff7ece9bd4a3ae7409d47b781"), 435 },
  { to_bytes<20>("b050c35601ef94b69e903c60433e0f098905bb19"), 115 },
  { to_bytes<20>("b2cfa66b7ada0f602ac2bcd33aae3ef0c6af746a"), 2451 },
  { to_bytes<20>("b2d60331966591168cfbb151f8377e63891e87c1"), 2253 },
  { to_bytes<20>("b536fc03676b226b0b09154544b97f88a155eea9"), 3056 },
  { to_bytes<20>("bbc2c7adf9a9dc6087f2ad40722fdce7037f1651"), 343 },
  { to_bytes<20>("bd9d05ec2cf0cecda46e6837b7d6f7dbac79ae69"), 3795 },
  { to_bytes<20>("c0593c7348f3083484d8e3d708a1871febe26659"), 995 },
  { to_bytes<20>("c2eb79e407b853966a4e0b0c016b6fe08f565c5c"), 171 },
  { to_bytes<20>("c3a331125c2f594cf131dc00fd9f4340e194c0e5"), 312 },
  { to_bytes<20>("c9aaefa49129d2d1240f0d66362fe51dc722a680"), 239 },
  { to_bytes<20>("c9fcde4c72df876ea7586e2b49e20c15a3724899"), 2784 },
  { to_bytes<20>("cc45d942931a98da3da4d690de1ed1d2063284ca"), 262 },
  { to_bytes<20>("cd177ebdc23c7798852e6beb6c53072e435545f8"), 1261 },
  { to_bytes<20>("ce3ceb88c211dffa6788113a3b43ef6624db293c"), 343 },
  { to_bytes<20>("cfbe0007014a5a2cff96b0929664c174e3fc06c1"), 1352 },
  { to_bytes<20>("d10e1971a4155fe0caafb60e022ec6687bee4ba3"), 573 },
  { to_bytes<20>("db95884ed933a5c3e40f788c55d928f18e2a842f"), 1131919 },
  { to_bytes<20>("de18e464da943e8b69b3f84ecbfd6cdb28b996de"), 305862 },
  { to_bytes<20>("df7c40b52a03b081387be031c01c5b4a0fffd1af"), 188 },
  { to_bytes<20>("dfe6bd41723efa523ab700b5f6e8451b954bf81a"), 55442 },
  { to_bytes<20>("e21f085615f98d3751690c1615923e89160d5783"), 6140 },
  { to_bytes<20>("e3cc51c54197fdcd477a73e7f8a0b6b55eaa8478"), 6140 },
  { to_bytes<20>("e3ddc110e667da2893df8ea3f60b2d2131e075f0"), 1121163888 },
  { to_bytes<20>("e4ae099d7eba7990167adea3342b84bb9b547e5f"), 26 },
  { to_bytes<20>("e57a476cce72c8cdb014c8474db21c40df4e8151"), 44338 },
  { to_bytes<20>("ec05c2999ecf1bee1703136614b2105eb8d02cfe"), 46943853 },
  { to_bytes<20>("ed5a07bd2a8f19927d53270daf294cf72de099b6"), 173 },
  { to_bytes<20>("f0b7c7852b0ac6d9bbdee6b0efca1907ccea1b43"), 2756 },
  { to_bytes<20>("f4d63dcd3df553fbb32eae4b2f52ab8ebf1827a7"), 14676 },
  { to_bytes<20>("f612e2226b9a75ad6f70639446ab252e006fe6f7"), 372 },
  { to_bytes<20>("f731f25127744a1d340fd061b16dbd241051acb8"), 279 },
  { to_bytes<20>("f85a7e62b84e0400c0f0e69017187b63c05a4570"), 1065 },
  { to_bytes<20>("f9b4e1f0912b51096e60e51affa4b8ee9582add8"), 1376 },
  { to_bytes<20>("f9eac6121a7f4bd117f0953e2f9f691b0db307fa"), 1104 },
  { to_bytes<20>("fa54091007e91cd14ba99e42c03b72defbfd9043"), 1028 },
  { to_bytes<20>("fc4508e84ff605ef872d9eab553d8d63f27cd68a"), 2426 },
  { to_bytes<20>("fc79cd2c2685a0fe0ca178a41de6c7d7830e98ca"), 778 },
  { to_bytes<20>("fc824043658c86424b5f2d480134dce7b004143d"), 472 }
};

const std::vector<std::pair<std::array<uint8_t,20>, uint64_t>> test1_out{
  { to_bytes<20>("0000000000000000000000000000000000000000"), 1234 },
  { to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"), 5678 },
  { to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"), 0xFFFFFFFFFFFFFFFF }
};

const std::vector<char> test1_data = read_file("test/test1.hset");

TEST_CASE("parse_headerTest") {
  auto beg = reinterpret_cast<const uint8_t*>(test1_data.data());
  auto end = beg + test1_data.size();

  auto act = make_unique_del(parse_header(beg, end), sfhash_destroy_hashset_info);
  REQUIRE(test1_info == *act);
}

TEST_CASE("expected_indexTest") {
  const std::vector<std::tuple<std::array<uint8_t,20>, uint32_t, uint32_t>> tests{
    {to_bytes<20>("0000000000000000000000000000000000000000"), 1000,   0},
    {to_bytes<20>("7fffffffffffffffffffffffffffffffffffffff"), 1000, 499},
    {to_bytes<20>("8000000000000000000000000000000000000000"), 1000, 500},
    {to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"), 1000, 999}
  };

  for (const auto& t: tests) {
    REQUIRE(std::get<2>(t) ==
                       expected_index(std::get<0>(t).data(), std::get<1>(t)));
  }
}

TEST_CASE("compute_radiusTest") {
  std::vector<std::array<uint8_t, 20>> hashes;
  for (const auto& p: test1_in) {
    hashes.push_back(p.first);
  }

  REQUIRE(
    test1_info.radius ==
    compute_radius(hashes.data(), hashes.data() + hashes.size())
  );
}

template <typename Hashes>
void api_tester(const HashSetInfo& hsinfo_exp, const std::vector<char> data, const Hashes& ins, const Hashes& outs) {
  SFHASH_Error* err = nullptr;

  auto hsinfo_act = make_unique_del(
    sfhash_load_hashset_info(data.data(), data.data() + data.size(), &err),
    sfhash_destroy_hashset_info
  );

  REQUIRE(!err);
  REQUIRE(hsinfo_act);
  REQUIRE(hsinfo_exp == *hsinfo_act);

  auto beg = data.data() + hsinfo_act->hashset_off;
  auto end = beg + hsinfo_act->hashset_size * hsinfo_act->hash_length;

  auto hs = make_unique_del(
    sfhash_load_hashset(data.data(), data.data() + data.size(), &err),
    sfhash_destroy_hashset
  );
  REQUIRE(!err);
  REQUIRE(hs);

  beg = data.data() + hsinfo_act->sizes_off;
  end = beg + hsinfo_act->hashset_size * sizeof(uint64_t);

  auto ss = make_unique_del(
    sfhash_load_sizeset(hsinfo_act.get(), beg, end, &err),
    sfhash_destroy_sizeset
  );
  REQUIRE(!err);
  REQUIRE(ss);

  std::array<uint8_t, 20> hash;
  uint64_t size;

  // ins are in
  for (const auto& p: ins) {
    std::tie(hash, size) = p;
    REQUIRE(sfhash_lookup_hashset(hs.get(), hash.data()));
    REQUIRE(sfhash_lookup_sizeset(ss.get(), size));
  }

  // outs are out
  for (const auto& p: outs) {
    std::tie(hash, size) = p;
    REQUIRE(!sfhash_lookup_hashset(hs.get(), hash.data()));
    REQUIRE(!sfhash_lookup_sizeset(ss.get(), size));
  }
}

TEST_CASE("hashset_api_Test") {
  api_tester(test1_info, test1_data, test1_in, test1_out);
}

TEST_CASE("bogus_hashset_Test") {
  const char bogus[] = "Not reall a hash set wrong wrong wrong";

  SFHASH_Error* err = nullptr;

  auto hs = make_unique_del(
    sfhash_load_hashset(bogus, bogus + sizeof(bogus), &err),
    sfhash_destroy_hashset
  );

  REQUIRE(err);
}

/*
TEST_CASE("nsrlTest") {
  char header[4096];

  int fd = open("test/nsrl.hset", O_RDONLY);
  REQUIRE(fd != -1);

  const ssize_t r = read(fd, header, sizeof(header));
  REQUIRE(sizeof(header) == r);

  SFHASH_Error* err = nullptr;

  auto hsinfo = make_unique_del(
    sfhash_load_hashset_info(header, header + sizeof(header), &err),
    sfhash_destroy_hashset_info
  );

  REQUIRE(!err);
  REQUIRE(hsinfo);

  const size_t len = hsinfo->hashset_size * hsinfo->hash_length;
  void* beg = mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, hsinfo->hashset_off);
  const void* end = static_cast<const char*>(beg) + len;

  REQUIRE(beg != MAP_FAILED);

  auto hs = make_unique_del(
    sfhash_load_hashset(hsinfo.get(), beg, end, true, &err),
    sfhash_destroy_hashset
  );

  REQUIRE(!err);
  REQUIRE(hs);

  const auto start = std::chrono::system_clock::now();
  REQUIRE(
    hsinfo->radius ==
    compute_radius<20>(static_cast<const std::array<uint8_t, 20>*>(beg),
                       static_cast<const std::array<uint8_t, 20>*>(end))
  );
  const auto stop = std::chrono::system_clock::now();
  std::cerr << hsinfo->radius << ' ' << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count() << "ms" << std::endl;

  munmap(beg, len);
  close(fd);
}
*/
