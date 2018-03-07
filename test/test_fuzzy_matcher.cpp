#include <scope/test.h>
#include "fuzzy_matcher.h"

void check_decode_chunks(const std::string& hash, const std::vector<uint64_t>& e) {
  const auto a = decode_chunks(hash);
  SCOPE_ASSERT_EQUAL(e.size(), a.size());

  auto epos = std::begin(e);
  const auto eend = std::end(e);

  for(; epos != eend; ++epos) {
    const auto search = a.find(*epos);
    SCOPE_ASSERT(search != a.end());
  }
}

SCOPE_TEST(test_parse_valid_sig) {
  const std::string sig = "192:RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV:R4qzN+idbyboj19xRRZE2IkWO/5Z,\"configure\"\"\".ac\"";
  const char *beg = sig.c_str(), *end = sig.c_str() + sig.length();
  const FuzzyHash hash(beg, end);

  SCOPE_ASSERT_EQUAL(0, validate_hash(beg, end));
  SCOPE_ASSERT_EQUAL(192, hash.blocksize());
  SCOPE_ASSERT_EQUAL("RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV", hash.block());
  SCOPE_ASSERT_EQUAL("R4qzN+idbyboj19xRRZE2IkWO/5Z", hash.double_block());
  SCOPE_ASSERT_EQUAL("configure\"\"\".ac", hash.filename());
}

SCOPE_TEST(test_parse_valid_sig_no_filename) {
  const std::string sig = "192:RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV:R4qzN+idbyboj19xRRZE2IkWO/5Z";
  const char *beg = sig.c_str(), *end = sig.c_str() + sig.length();
  const FuzzyHash hash(beg, end);

  SCOPE_ASSERT_EQUAL(1, validate_hash(beg, end));
  SCOPE_ASSERT_EQUAL(192, hash.blocksize());
  SCOPE_ASSERT_EQUAL("RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV", hash.block());
  SCOPE_ASSERT_EQUAL("R4qzN+idbyboj19xRRZE2IkWO/5Z", hash.double_block());
  SCOPE_ASSERT_EQUAL("", hash.filename());
}

SCOPE_TEST(test_parse_invalid_sig) {
  const std::vector<std::string> tests = { "abcd", "6:abcd:defg,\"no_trailing_quote", "" };
  for (const auto& s: tests) {
    SCOPE_ASSERT_EQUAL(1, validate_hash(s.c_str(), s.c_str()+s.length()));
  }
}

SCOPE_TEST(test_decode_small_chunk) {
  const std::string hash = "SNsFov";
  const std::vector<uint64_t> expected = { 2718292808 };
  check_decode_chunks(hash, expected);
}

SCOPE_TEST(test_decode_empty) {
  const std::string hash = "";
  const std::vector<uint64_t> expected = { 0 };
  check_decode_chunks(hash, expected);
}

SCOPE_TEST(test_decode_single_character) {
  const std::string hash = "t";
  const std::vector<uint64_t> expected = { 180 };
  check_decode_chunks(hash, expected);
}

SCOPE_TEST(test_decode_padding) {
  const std::string hash = "sWEyn";
  const std::vector<uint64_t> expected = { 2620547505 };
  check_decode_chunks(hash, expected);
}

SCOPE_TEST(test_decode_chunks) {
  const std::string hash = "HEI9Xg7+P9yImaNk3qrDwpXe9gf5xkIZ";
  const std::vector<uint64_t> expected = {
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
  check_decode_chunks(hash, expected);
}

SCOPE_TEST(test_load_fuzzy) {
  std::string data = "ssdeep,1.1--blocksize:hash:hash,filename\n"
                     "192:RZawL6QiUA4t+idbepZN0Dj19Lwm3RKiZE2IPcWO/5jV:R4qzN+idbyboj19xRRZE2IkWO/5Z,\"configure.ac\"\n"
                     "6144:Ux9sXthkMmK4C4VRp7Q8QPTxoToVLGv8Hde2w7i9grh+B8Q+pDKHTvKWNpYrXYnL:oIbG4zHdizhHib9iBMoW,\"configure\"";

  auto matcher = load_fuzzy_hashset(data.c_str(), data.c_str() + data.length());
  SCOPE_ASSERT(matcher.get());
}

void check_max_score(const std::string& data, const std::string& sig, int expected_count, int expected_max) {
  auto matcher = load_fuzzy_hashset(data.c_str(), data.c_str() + data.length());
  const int result_count = sfhash_fuzzy_matcher_compare(matcher.get(), sig.c_str(), sig.c_str()+sig.length());
  SCOPE_ASSERT_EQUAL(expected_count, result_count);

  int max = 0;
  for (int i = 0; i < result_count; ++i) {
    const auto& result = matcher->get_match(i);
    max = std::max(max, result->score);
  }
  SCOPE_ASSERT_EQUAL(expected_max, max);
}

SCOPE_TEST(test_find_match) {
  const std::string data = "ssdeep,1.1--blocksize:hash:hash,filename\n"
                           "6:S+W9pdFFwj+Q4HRhOhahxlA/FG65WOCWn9Q6Wg9r939:TmAgxho/r5Wun9Q6p9r9t,\"a.txt\"\n"
                           "6:S5O61sdFFwj+Q4HRhOhahxlA/FG65WOCWn9hy9r9eF:gmAgxho/r5Wun9o9r9a,\"b.txt\"\n"
                           "6:STLdFFwj+Q4HRhOhahxlA/FG65WOCWn9kKF9r9TKO:wLAgxho/r5Wun9k89r9TJ,\"c.txt\"\n"
                           "6:Sm5dFFwj+Q4HRhOhahxlA/FG65WOCWn9l2F9r9xI2O:T5Agxho/r5Wun9lI9r9xIl,\"d.txt\"\n"
                           "6:SDssdFFwj+Q4HRhOhahxlA/FG65WOCWn9nRk89r9KRkJ:YAgxho/r5Wun9RR9r9KRa,\"e.txt\"\n"
                           "6:SS7Lp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9nv7LZW9r9KzLZ3:T7LLAgxho/r5Wun9v7LZW9r9KzLZ3,\"a.txt\"\n"
                           "6:S8QLdFFwj+Q4HRhOhahxlA/FG65WOCWn91KRu9r9YlIv:XKAgxho/r5Wun91K89r9j,\"a.txt\"\n"
                           "6:SXp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9TF9r9a9O:m5Agxho/r5Wun9h9r9aU,\"a.txt\"\n"
                           "6:Si65dFFwj+Q4HRhOhahxlA/FG65WOCWn9rTF9r9iTO:q5Agxho/r5Wun919r9v,\"a.txt\"\n"
                           "6:SIJS5dFFwj+Q4HRhOhahxlA/FG65WOCWn9S6J7F9r9zBi7O:9JS5Agxho/r5Wun9H7F9r907O,\"a.txt\"\n"
                           "6:Sdcp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9n89r9WJ:Dp5Agxho/r5Wun9n89r9WJ,\"a.txt\"\n"
                           "6:SHHsdFFwj+Q4HRhOhahxlA/FG65WOCWn9oFF9r9HFO:SsAgxho/r5Wun9EF9r9lO,\"a.txt\"\n"
                           "6:SIoFsdFFwj+Q4HRhOhahxlA/FG65WOCWn9Ng9r9I9:9Agxho/r5Wun9a9r9k,\"a.txt\"\n"
                           "6:Scw/dFFwj+Q4HRhOhahxlA/FG65WOCWn9nhwg9r9K69:uAgxho/r5Wun999r9KG,\"a.txt\"\n"
                           "6:SY5dFFwj+Q4HRhOhahxlA/FG65WOCWn90F9r9VO:r5Agxho/r5Wun9a9r98,\"a.txt\"\n";
  const std::string sig = "6:S8y5dFFwj+Q4HRhOhahxlA/FG65WOCWn9M9r9Rg:Ty5Agxho/r5Wun9M9r9Rg";

  check_max_score(data, sig, 30, 80);
}

SCOPE_TEST(test_find_match_suffix) {
  // Hash blocks have a common suffix
  const std::string data = "ssdeep,1.1--blocksize:hash:hash,filename\n"
                           "3:Z3FOlll+leh/kreWWe05OrLO516xr5/16n4bGWfqKMLkcTitn:Z3FK/aeh/1KMKr57bGWyx6,\"a.txt\"\n";
  const std::string sig = "3:ZklllCllGrOj28lhGKZzllNzXsmf5jDHO5oERE2J5xAIGIJi/2XnXLkcTitn:ZsaOrOS87dZzllSo5jDuPi23fPGSnx6";

  check_max_score(data, sig, 1, 36);
}
