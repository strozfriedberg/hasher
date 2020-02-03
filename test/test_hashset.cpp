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
  1,                   // version
  "SHA1",              // hash type
  20,                  // hash length
  0,                   // flags
  "Some test hashes",  // hashset name
  100,                 // hashset size
  8,                  // radius
  "Test! Test! Test!", // hashset description
  to_bytes<32>("ab5e251d1d3f584b992be456f7338fb7d472ea2bd26ca72768cd8ebffb0072b5") // hashset SHA256
};

const std::vector<std::array<uint8_t, 20>> test1_in{
  to_bytes<20>("00f273108f90581d30e1c5a5c4b487648704d915"),
  to_bytes<20>("03a5adafed2d9ccc01e124cb5997b4856ea5a267"),
  to_bytes<20>("03dd8209839a18f7a65e23d752fb6733a4723337"),
  to_bytes<20>("06914dee4a7476ba2d501b9cfb8807397ea51fbc"),
  to_bytes<20>("0b13ac9525b952e63b3f26db254d77978b71d36b"),
  to_bytes<20>("0facb15a97652ef6b7241fa70f4b434683f3b855"),
  to_bytes<20>("0fbb533c9f59d651f0f179a837986938b1c63498"),
  to_bytes<20>("0fcbf8485a995171fa5b620033b18b05a6743a02"),
  to_bytes<20>("11dfb7edc29cfd549139360d3c8cfd183641b74d"),
  to_bytes<20>("11efaab06d832d4e1fd096e6177a301c04ebbf7a"),
  to_bytes<20>("150794e9c2aa1fbd3a3b6ac29db7f54ad8a38386"),
  to_bytes<20>("15cbce5e52aef51353b89620df06febd729f5da7"),
  to_bytes<20>("176d0e3009b1a93cf893c452da3058e11e64a388"),
  to_bytes<20>("19600d3802865ea0fab064de398297f89f32c0ec"),
  to_bytes<20>("1a11268cbf5266153e1743da8a47d0760299a04d"),
  to_bytes<20>("1a243f98d580156b79e53655e8d8d45507380eb0"),
  to_bytes<20>("1aa676453bf2e26f0808617315919cba126a4494"),
  to_bytes<20>("1ce78579bff760133bdcafa020895dbdaa2db78d"),
  to_bytes<20>("1dc6abd6c4a5f2b1a4e1e997817dddf8d7066d3f"),
  to_bytes<20>("213ca262bf6af12428d42842848464565f3d5504"),
  to_bytes<20>("217e04a768f3c9407fcc1cca1838651e6aa02326"),
  to_bytes<20>("27f80fbe460bae8a0540bd9b92d486a5beca3271"),
  to_bytes<20>("2be37b9beced2e08ae7283eb3870e4f4862c1565"),
  to_bytes<20>("2c96685edfc67603af54c87ec5613b4d3d6a98ff"),
  to_bytes<20>("2e8c8793d4dc7201d2d51af62ba72f31983fabff"),
  to_bytes<20>("3037bdadbd52b3951e8e632b1cfcced1197db8f7"),
  to_bytes<20>("309f99a7a0c1281c67726a9e8f9e2f97ddb337a7"),
  to_bytes<20>("37f8839889b9042a7d30f986f4001770bd6a2ee5"),
  to_bytes<20>("3b130f464fabf3a0a785f37c637707ad1da139e9"),
  to_bytes<20>("4380cba6f07d94ec88b7e3691d92bb9701ee0f6a"),
  to_bytes<20>("44982ad16f76f8ec9d800f2e9907612e744103fa"),
  to_bytes<20>("44f216a2b403d14697efa56b2a76f9791cfe70b4"),
  to_bytes<20>("4781f5ef84f50c70a6eb6b056b28801ecd69634c"),
  to_bytes<20>("4826ae3a4cf10210611565be6a9f01daf0f9b1c3"),
  to_bytes<20>("488cc25ae35b0f6b5f1c39f1b24fbbc132334c14"),
  to_bytes<20>("48f289423db64a6095bf671ee217d36a940cb870"),
  to_bytes<20>("5141d8137ea32e3b1bfe5b48717ca6d3a15e8474"),
  to_bytes<20>("56540639e0f06c1170f1186ba1a3f0fc609136a7"),
  to_bytes<20>("5dd0d0918b76df031bd174854042638a37c4d874"),
  to_bytes<20>("5eabf38abf07cac7796fd962d6a8413b49112798"),
  to_bytes<20>("61a405778b497ff90ea8a554440733a00f35ae51"),
  to_bytes<20>("61c0d3f83219a7a6e755fb5fb48fc8f74e57c2b8"),
  to_bytes<20>("64144afb56b971c0dd96554cf2e1d6c4842c89e6"),
  to_bytes<20>("65fa9ffb58e2b545e0b201c35f1a0b396162981c"),
  to_bytes<20>("67c8652d15e22981cabf8f6557a05776fcfad9cd"),
  to_bytes<20>("6871957156b07ae46e5f75da9510a56c79b45c76"),
  to_bytes<20>("6934105ad50010b814c933314b1da6841431bc8b"),
  to_bytes<20>("694a085166224192128ef98dcfb35020be3dda2f"),
  to_bytes<20>("6e6fe68a1c82b57226ad1d048f9bc230892a3cdd"),
  to_bytes<20>("70c9696dc9ff62187f67147bd2c6d875f0318993"),
  to_bytes<20>("742e2e0d2c7f1b1285c1dde45916d66f474444a5"),
  to_bytes<20>("7f494424effae0613ef1beaa86927a5a27ac907c"),
  to_bytes<20>("812446541be88fd26035c059d2082285a0771635"),
  to_bytes<20>("829039dd44e5c58932f147b1636b02029607d076"),
  to_bytes<20>("82c6d8e61a9b81fe27c9783811538a4979c6a5cc"),
  to_bytes<20>("8624bcdae55baeef00cd11d5dfcfa60f68710a02"),
  to_bytes<20>("88e6aca412381d6d756e5562297fe98d09ae5ec9"),
  to_bytes<20>("893f9dd033f31b52ee8aad3e71bbe368e52a500b"),
  to_bytes<20>("8dc7fb8e9a404e88810d2521dbed30e7fcbaca86"),
  to_bytes<20>("92d38b1fcfc8ad5b072ad15c91814eb43d052161"),
  to_bytes<20>("946882072a51a8077bc75769ed93558000c11911"),
  to_bytes<20>("94855c4df08b7561a559139c0e030d82712e879f"),
  to_bytes<20>("97a3437214255cabf9e5c852125111289c5c28a0"),
  to_bytes<20>("9939741d31d8975deecd53271415a58af66b2f11"),
  to_bytes<20>("9db65b6225d4614a5bb36274f6e36555b0907631"),
  to_bytes<20>("a5a8cd3b92d8f5bed1d3cea9bc6cd060ce0f02f5"),
  to_bytes<20>("a8567df585db8248b5bc5b3a75d8bd0fed168a92"),
  to_bytes<20>("a95b0119a123798c28b16c7f6a611e5146e1ac79"),
  to_bytes<20>("ab644da4bb85946d00fc84f0d6850dbabc5653ff"),
  to_bytes<20>("ae752791f45e6c0101bc1f3d9edf9e97c62a780c"),
  to_bytes<20>("aef51decc245bc37c8f6c25b694403b0e0a50d6e"),
  to_bytes<20>("b050c35601ef94b69e903c60433e0f098905bb19"),
  to_bytes<20>("b45560cc8b55a4e067ea98941ceeb66be3d5f7d3"),
  to_bytes<20>("bcc2eab2abaee3eaae621e98b8d6a44c6ae774f3"),
  to_bytes<20>("bdc73880c6b0f3e5c433e7a13da6d3c10329c9ce"),
  to_bytes<20>("c307eb156af2672900fd91511416163b8e7e0ec6"),
  to_bytes<20>("c4a247f43f7e7876783d0e8960146d8130644ee5"),
  to_bytes<20>("c5a149f85ea743eacdbdbf3f03439dba2e48940b"),
  to_bytes<20>("c719ad39ff15ca6aa9bca8a8b7282058e56973d8"),
  to_bytes<20>("c73866e247d8ae4404d1934bd7b4ea7b15ff5958"),
  to_bytes<20>("c97176579d296100004955483f7c862daeac416b"),
  to_bytes<20>("caa616186ff066fc2109c3344881ae86ce6c4e92"),
  to_bytes<20>("cbe2e2473ed632ad7461c8e010ee6de135bba0e6"),
  to_bytes<20>("d055c41fdb5d61b6217fe4059fae950eeb25dab5"),
  to_bytes<20>("d07efcaf68c13693dbb0f6c19b8f469a83cfa6a1"),
  to_bytes<20>("d32cb2ea8b00c58386b9231570ae08e6ec0cf98b"),
  to_bytes<20>("d7766968033556d27ea144a908601e99c06dd961"),
  to_bytes<20>("ded713d2ef403a0c6beedd8b47023f736f96d4e8"),
  to_bytes<20>("e20c41b0740062375232472b9d547739ae15ad42"),
  to_bytes<20>("e23bcae3bce2cfea0ea9fe239fca5d6abbeb2ff4"),
  to_bytes<20>("e2f121f57a813b09293432b6be0dfebca350a629"),
  to_bytes<20>("e57a476cce72c8cdb014c8474db21c40df4e8151"),
  to_bytes<20>("e593c6c05675073e81dceb638696eef1ac9bcde9"),
  to_bytes<20>("ea0be9793e32b13ef137cb6c66d192eb073ccb20"),
  to_bytes<20>("eb302d5806d47484d3bb3e0ebfb561e5574cabe6"),
  to_bytes<20>("ec4e83909bbacf7d2b12121aa84a84d6a71ca687"),
  to_bytes<20>("f40dc6972ed3e2aec9bcbdc8bee8b080a0bf1eec"),
  to_bytes<20>("f4778f0b2e382a726c4f8c6c2694f0b4ba2bd008"),
  to_bytes<20>("f4d63dcd3df553fbb32eae4b2f52ab8ebf1827a7"),
  to_bytes<20>("fd18b71a6312212cd176a2de03ff9f6995e1cafb")
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
  SCOPE_ASSERT_EQUAL(
    test1_header.radius,
    compute_radius(test1_in.data(), test1_in.data() + test1_in.size())
  );
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
