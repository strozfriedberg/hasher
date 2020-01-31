#include "hashset.h"
#include "hasher/api.h"
#include "util.h"

#include <iostream>

#include <fstream>
#include <iterator>
#include <vector>

bool operator==(const Header& l, const Header& r) {
  return l.version == r.version &&
         l.hash_type == r.hash_type &&
         l.hash_length == r.hash_length &&
         l.flags == r.flags &&
         l.hashset_name == r.hashset_name &&
         l.hashset_size == r.hashset_size &&
         l.radius == r.radius &&
         l.hashset_desc == r.hashset_desc &&
         l.hashset_sha256 == r.hashset_sha256; 
}

std::ostream& operator<<(std::ostream& o, const Header& h) {
  o << '{'
    << h.version << ','
    << '"' << h.hash_type << "\","
    << h.hash_length << ','
    << h.flags << ','
    << '"' << h.hashset_name << "\","
    << h.hashset_size << ','
    << h.radius << ','
    << '"' << h.hashset_desc << "\","
    << to_hex(h.hashset_sha256.data(),
              h.hashset_sha256.data() + h.hashset_sha256.size())
    << '}';
  return o;
}

#include <scope/test.h>

std::vector<char> read_file(const std::string& path) {
  std::ifstream in(path, std::ios_base::binary);
  return std::vector<char>(std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>());
}

const Header test1_header{
  1,                  // version
  "SHA1",             // hash type
  20,                 // hash length
  0,                  // flags
  "Some test hashes", // hashset name
  100,                // hashset size
  10,                 // radius
  "TEST!",            // hashset description
  to_bytes<32>("3d06fb49eb1cef1466b1dd7f01339bea3ec6cd2f9d5b540523b5f7841a97ac69") // hashset SHA256
};

const std::vector<std::array<uint8_t, 20>> test1_in{
  to_bytes<20>("03056bc08003a879889005a316b5f9159b1cba5a"),
  to_bytes<20>("04d4b13b2cf44056a14a1550640492a907469e9e"),
  to_bytes<20>("071845537205a14ce14d6e05754ccaacd77985a5"),
  to_bytes<20>("107573c2f4809bbf0b46570063362a8ab4082a80"),
  to_bytes<20>("10cb8e2d8b8c4ec01af5d04efc21908ee24eedd6"),
  to_bytes<20>("12361014ba6cb7dc695c523c8c13cbff5cfbbe38"),
  to_bytes<20>("12a4898b9c77c746c4cc1661706597975b43fa0d"),
  to_bytes<20>("14ca1c6af0e0e43f8c4b40bc5bbd236aab4c5ea7"),
  to_bytes<20>("1ed6c5b149b19bb08c1402bf11be2ce9ce772e07"),
  to_bytes<20>("2028bffadfd9b989bcc63da90596101fe4ec20b9"),
  to_bytes<20>("217e04a768f3c9407fcc1cca1838651e6aa02326"),
  to_bytes<20>("25f278e3467ebda53027fc7eb3e41ab05b40f009"),
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
  to_bytes<20>("7006e20b5e75cff10788ac675c87fae7f59b2993"),
  to_bytes<20>("704239535a35062c45ecad41a6f95649f6bb806f"),
  to_bytes<20>("70c9696dc9ff62187f67147bd2c6d875f0318993"),
  to_bytes<20>("74bf89f63e5a0743e26d1dd0fd3199e719034079"),
  to_bytes<20>("74c05baef5d03497b9800d470bd8c824e57ff7af"),
  to_bytes<20>("7d69abfd75a2e89aba37e9eb404fa5aea3d7a6f8"),
  to_bytes<20>("8926519e4c57579b7a02dbab9486c80e6ba5b328"),
  to_bytes<20>("92952baf4a0e0ac41170b3138924a72dbeef0983"),
  to_bytes<20>("983f40b44129915538e7764ce4f550f3a010caa8"),
  to_bytes<20>("9939741d31d8975deecd53271415a58af66b2f11"),
  to_bytes<20>("9a2834df62ca06ee0a14d96449a4d0c394d04642"),
  to_bytes<20>("9bd8e3294486abffa3974e4ac2d040937a80f604"),
  to_bytes<20>("9bf0d513e6354e69935a000d98f374003fac2023"),
  to_bytes<20>("9c2c5142584d081c219be587bd49616b4d8b1d98"),
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
  to_bytes<20>("f45c93850da2a56e3791efc993b1178c24a5dd49"),
  to_bytes<20>("f4d63dcd3df553fbb32eae4b2f52ab8ebf1827a7"),
  to_bytes<20>("f612e2226b9a75ad6f70639446ab252e006fe6f7"),
  to_bytes<20>("f731f25127744a1d340fd061b16dbd241051acb8"),
  to_bytes<20>("f85a7e62b84e0400c0f0e69017187b63c05a4570"),
  to_bytes<20>("f9eac6121a7f4bd117f0953e2f9f691b0db307fa"),
  to_bytes<20>("fa54091007e91cd14ba99e42c03b72defbfd9043"),
  to_bytes<20>("fc4508e84ff605ef872d9eab553d8d63f27cd68a"),
  to_bytes<20>("fc79cd2c2685a0fe0ca178a41de6c7d7830e98ca"),
  to_bytes<20>("fc824043658c86424b5f2d480134dce7b004143d")
};

const std::vector<std::array<uint8_t,20>> test1_out{
  to_bytes<20>("0000000000000000000000000000000000000000"),
  to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
  to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff")
};

const std::vector<char> test1_data = read_file("test/test1.hset");

SCOPE_TEST(parse_headerTest) {
  const Header act = parse_header(test1_data.data(),
                                  test1_data.data() + test1_data.size());
  SCOPE_ASSERT_EQUAL(test1_header, act);
}

SCOPE_TEST(expected_indexTest) {
  const std::vector<std::tuple<std::array<uint8_t,20>, uint32_t, uint32_t>> tests{
    {to_bytes<20>("0000000000000000000000000000000000000000"), 1000,   0},
    {to_bytes<20>("7fffffffffffffffffffffffffffffffffffffff"), 1000, 499},
    {to_bytes<20>("8000000000000000000000000000000000000000"), 1000, 500},
    {to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"), 1000, 999}
  };

  for (const auto& t: tests) { 
    SCOPE_ASSERT_EQUAL(std::get<2>(t),
                       expected_index(std::get<0>(t).data(), std::get<1>(t)));
  }
}

SCOPE_TEST(compute_radiusTest) {
  SCOPE_ASSERT_EQUAL(10, compute_radius(test1_in.data(), test1_in.data() + test1_in.size()));
}

template <typename Hashes>
void api_tester(const Header& header, const std::vector<char> data, const Hashes& hashes, const Hashes& nonhashes, bool shared) {
  HasherError* err = nullptr;

  std::unique_ptr<HashSet, void(*)(HashSet*)> hs(
    sf_load_hashset_header(data.data(), data.data() + data.size(), &err),
    sf_destroy_hashset
  );

  SCOPE_ASSERT(hs);
  SCOPE_ASSERT(!err);

  // stuff from the header
  SCOPE_ASSERT_EQUAL(header.hashset_name, sf_hashset_name(hs.get()));
  SCOPE_ASSERT_EQUAL(header.hashset_desc, sf_hashset_description(hs.get()));
  SCOPE_ASSERT_EQUAL(header.hashset_size, sf_hashset_size(hs.get()));
  SCOPE_ASSERT_EQUAL(header.hash_type, sf_hash_type(hs.get()));
  SCOPE_ASSERT_EQUAL(header.hash_length, sf_hash_length(hs.get()));

  sf_load_hashset_data(hs.get(), data.data() + 4096, data.data() + data.size(), true, &err); 
  SCOPE_ASSERT(!err);

  // in hashes are in
  for (const auto& h: hashes) {
    SCOPE_ASSERT(sf_lookup_hashset(hs.get(), h.data()));
  }

  // out hashes are out
  for (const auto& h: nonhashes) {
    SCOPE_ASSERT(!sf_lookup_hashset(hs.get(), h.data()));
  }
}

SCOPE_TEST(hashset_shared_api_Test) {
  api_tester(test1_header, test1_data, test1_in, test1_out, true);
}

SCOPE_TEST(hashset_copied_api_Test) {
  api_tester(test1_header, test1_data, test1_in, test1_out, false);
}
