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

SCOPE_TEST(test_decode_small_chunk) {
  std::string hash = "SNsFov";
  std::vector<uint64_t> expected = { 2718292808 };

  auto actual = decode_chunks(hash);
  SCOPE_ASSERT_EQUAL(expected.size(), actual.size());

  for (size_t i = 0; i < expected.size(); ++i) {
    SCOPE_ASSERT(actual.find(expected[i]) != actual.end());
  }
}

SCOPE_TEST(test_decode_empty) {
  std::string hash = "";
  std::vector<uint64_t> expected = { 0 };

  auto actual = decode_chunks(hash);
  SCOPE_ASSERT_EQUAL(expected.size(), actual.size());

  for (size_t i = 0; i < expected.size(); ++i) {
    SCOPE_ASSERT(actual.find(expected[i]) != actual.end());
  }

}

SCOPE_TEST(test_decode_single_character) {
  std::string hash = "t";
  std::vector<uint64_t> expected = { 180 };

  auto actual = decode_chunks(hash);
  SCOPE_ASSERT_EQUAL(expected.size(), actual.size());

  for (size_t i = 0; i < expected.size(); ++i) {
    SCOPE_ASSERT(actual.find(expected[i]) != actual.end());
  }
}

SCOPE_TEST(test_decode_padding) {
  std::string hash = "sWEyn";
  std::vector<uint64_t> expected = { 2620547505 };

  auto actual = decode_chunks(hash);
  SCOPE_ASSERT_EQUAL(expected.size(), actual.size());

  for (size_t i = 0; i < expected.size(); ++i) {
    SCOPE_ASSERT(actual.find(expected[i]) != actual.end());
  }
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
    577949007489,
  };
  auto actual = decode_chunks(hash);
  SCOPE_ASSERT_EQUAL(expected.size(), actual.size());

  for (size_t i = 0; i < expected.size(); ++i) {
    SCOPE_ASSERT(actual.find(expected[i]) != actual.end());
  }
}

SCOPE_TEST(test_load_fuzzy) {
  std::string data = "ssdeep,1.1--blocksize:hash:hash,filename\n" \
                     "192:RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV:R4qzN+idbyboj19xRRZE2IkWO/5Z,\"configure.ac\"\n" \
                     "6144:Ux9sXthkMmK4C4VRp7Q8QPTxoToVLGv8Hde2w7i9grh+B8Q+pDKHTvKWNpYrXYnL:oIbG4zHdizhHib9iBMoW,\"configure\"";

  auto matcher = load_fuzzy_hashset(data.c_str(), data.c_str() + data.length());

}

SCOPE_TEST(test_find_match) {
  std::string data = "ssdeep,1.1--blocksize:hash:hash,filename\n" \
                     "6:S+W9pdFFwj+Q4HRhOhahxlA/FG65WOCWn9Q6Wg9r939:TmAgxho/r5Wun9Q6p9r9t,\"a.txt\"\n" \
                     "6:S5O61sdFFwj+Q4HRhOhahxlA/FG65WOCWn9hy9r9eF:gmAgxho/r5Wun9o9r9a,\"b.txt\"\n" \
                     "6:STLdFFwj+Q4HRhOhahxlA/FG65WOCWn9kKF9r9TKO:wLAgxho/r5Wun9k89r9TJ,\"c.txt\"\n" \
                     "6:Sm5dFFwj+Q4HRhOhahxlA/FG65WOCWn9l2F9r9xI2O:T5Agxho/r5Wun9lI9r9xIl,\"d.txt\"\n" \
                     "6:SDssdFFwj+Q4HRhOhahxlA/FG65WOCWn9nRk89r9KRkJ:YAgxho/r5Wun9RR9r9KRa,\"e.txt\"\n";
                     "6:SS7Lp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9nv7LZW9r9KzLZ3:T7LLAgxho/r5Wun9v7LZW9r9KzLZ3,\"a.txt\"\n" \
                     "6:S8QLdFFwj+Q4HRhOhahxlA/FG65WOCWn91KRu9r9YlIv:XKAgxho/r5Wun91K89r9j,\"a.txt\"\n" \
                     "6:SXp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9TF9r9a9O:m5Agxho/r5Wun9h9r9aU,\"a.txt\"\n" \
                     "6:Si65dFFwj+Q4HRhOhahxlA/FG65WOCWn9rTF9r9iTO:q5Agxho/r5Wun919r9v,\"a.txt\"\n" \
                     "6:SIJS5dFFwj+Q4HRhOhahxlA/FG65WOCWn9S6J7F9r9zBi7O:9JS5Agxho/r5Wun9H7F9r907O,\"a.txt\"\n" \
                     "6:Sdcp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9n89r9WJ:Dp5Agxho/r5Wun9n89r9WJ,\"a.txt\"\n" \
                     "6:SHHsdFFwj+Q4HRhOhahxlA/FG65WOCWn9oFF9r9HFO:SsAgxho/r5Wun9EF9r9lO,\"a.txt\"\n" \
                     "6:SIoFsdFFwj+Q4HRhOhahxlA/FG65WOCWn9Ng9r9I9:9Agxho/r5Wun9a9r9k,\"a.txt\"\n" \
                     "6:Scw/dFFwj+Q4HRhOhahxlA/FG65WOCWn9nhwg9r9K69:uAgxho/r5Wun999r9KG,\"a.txt\"\n" \
                     "6:SY5dFFwj+Q4HRhOhahxlA/FG65WOCWn90F9r9VO:r5Agxho/r5Wun9a9r98,\"a.txt\"\n";



  auto matcher = load_fuzzy_hashset(data.c_str(), data.c_str() + data.length());
  std::string sig = "6:S8y5dFFwj+Q4HRhOhahxlA/FG65WOCWn9M9r9Rg:Ty5Agxho/r5Wun9M9r9Rg";
  int result_count = sfhash_fuzzy_matcher_compare(matcher.get(), sig.c_str());
  SCOPE_ASSERT_EQUAL(10, result_count);

  int max = 0;
  for (int i = 0; i < result_count; ++i) {
    auto result = matcher->get_match(i);
    max = std::max(max, result->score);
  }
  SCOPE_ASSERT_EQUAL(80, max);
}

SCOPE_TEST(test_find_match_suffix) {
  std::string data = "ssdeep,1.1--blocksize:hash:hash,filename\n" \
                     "3:Z3FOlll+leh/kreWWe05OrLO516xr5/16n4bGWfqKMLkcTitn:Z3FK/aeh/1KMKr57bGWyx6,\"a.txt\"\n";
  // Hash blocks have a common suffix

  auto matcher = load_fuzzy_hashset(data.c_str(), data.c_str() + data.length());
  std::string sig = "3:ZklllCllGrOj28lhGKZzllNzXsmf5jDHO5oERE2J5xAIGIJi/2XnXLkcTitn:ZsaOrOS87dZzllSo5jDuPi23fPGSnx6";
  int result_count = sfhash_fuzzy_matcher_compare(matcher.get(), sig.c_str());
  SCOPE_ASSERT_EQUAL(1, result_count);

  int max = 0;
  for (int i = 0; i < result_count; ++i) {
    auto result = matcher->get_match(i);
    max = std::max(max, result->score);
  }
  SCOPE_ASSERT_EQUAL(36, max);

}
