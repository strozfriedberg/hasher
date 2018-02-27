#include <scope/test.h>
#include "fuzzy_matcher.h"


SCOPE_TEST(test_parse_valid_sig) {
  std::string sig = "192:RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV:R4qzN+idbyboj19xRRZE2IkWO/5Z,\"configure\"\"\".ac\"";

  std::unique_ptr<FuzzyHash> hash = parse_sig(sig.c_str());
  SCOPE_ASSERT_EQUAL(192, hash->blocksize);
  SCOPE_ASSERT_EQUAL("RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV", hash->s1);
  SCOPE_ASSERT_EQUAL("R4qzN+idbyboj19xRRZE2IkWO/5Z", hash->s2);
  SCOPE_ASSERT_EQUAL("configure\"\"\".ac", hash->filename);
}

SCOPE_TEST(test_parse_invalid_sig) {
  SCOPE_ASSERT(!parse_sig("abcd"));
  SCOPE_ASSERT(!parse_sig(""));
  SCOPE_ASSERT(!parse_sig("6:abcd:defg,\"no_trailing_quote"));
}
