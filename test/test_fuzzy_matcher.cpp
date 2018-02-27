#include <scope/test.h>
#include "fuzzy_matcher.h"


SCOPE_TEST(test_parse_valid_sig) {
  std::string sig = "192:RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV:R4qzN+idbyboj19xRRZE2IkWO/5Z,\"configure\"\"\".ac\"";

  FuzzyHash hash(sig);
  SCOPE_ASSERT_EQUAL(0, hash.validate());
  SCOPE_ASSERT_EQUAL(192, hash.blocksize());
  SCOPE_ASSERT_EQUAL("RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV", hash.block());
  SCOPE_ASSERT_EQUAL("R4qzN+idbyboj19xRRZE2IkWO/5Z", hash.double_block());
  SCOPE_ASSERT_EQUAL("configure\"\"\".ac", hash.filename());
}

SCOPE_TEST(test_parse_invalid_sig) {
  SCOPE_ASSERT_EQUAL(1, FuzzyHash("abcd").validate());
  SCOPE_ASSERT_EQUAL(1, FuzzyHash("6:abcd:defg,\"no_trailing_quote").validate());
  SCOPE_ASSERT_EQUAL(1, FuzzyHash("").validate());
}

SCOPE_TEST(test_decode_chunks) {
  std::string hash = "HEI9Xg7+P9yImaNk3qrDwpXe9gf5xkIZ";
  std::vector<uint64_t> expected = {
    61710615068,
    822542307088,
    978982065443,
    1099381307637,
    945966419550,
    150182281091,
    591782601711,
    438664626168,
    702655552575,
    933755233015,
    331628579272,
    526461527586,
    733875577753,
    758770030952,
    260599074102,
    43212569235,
    643217730270,
    513885122730,
    1028060167340,
    929782237711,
    34206553538,
    1093098370981,
    672151957341,
    111251806331,
    286806050806,
  };
  std::vector<uint64_t> actual = decode_chunks(hash);
  SCOPE_ASSERT_EQUAL(expected.size(), actual.size());
  for (size_t i = 0; i < expected.size(); ++i) {
    SCOPE_ASSERT_EQUAL(expected[i], actual[i]);
  }
}

SCOPE_TEST(test_load_fuzzy) {
  std::string data = "ssdeep,1.1--blocksize:hash:hash,filename\n" \
                     "192:RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV:R4qzN+idbyboj19xRRZE2IkWO/5Z,\"configure.ac\"\n" \
                     "6144:Ux9sXthkMmK4C4VRp7Q8QPTxoToVLGv8Hde2w7i9grh+B8Q+pDKHTvKWNpYrXYnL:oIbG4zHdizhHib9iBMoW,\"configure\"";

  auto matcher = load_fuzzy_hashset(data.c_str(), data.c_str() + data.length());

}
