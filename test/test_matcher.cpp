#include <scope/test.h>

#include <cstring>

#include "hasher.h"
#include "matcher.h"
#include "util.h"

#include "pair_out.h"
#include "tuple_out.h"

template <size_t N>
std::ostream& operator<<(std::ostream& o, const hash_t<N>& h) {
  return o << to_hex(h);
}

SCOPE_TEST(tokenizeNonempty) {
  const char line[] = "abc\tdef\tg\nhijk\t\tlmnop\n";

  TokenIterator i(line, line + std::strlen(line));
  const TokenIterator end(line + std::strlen(line), line + std::strlen(line));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(line, line+3));
  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*++i, std::make_pair(line+4, line+7));
  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*++i, std::make_pair(line+8, line+9));
  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*++i, std::make_pair(line+10, line+14));
  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*++i, std::make_pair(line+15, line+15));
  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*++i, std::make_pair(line+16, line+21));
  SCOPE_ASSERT(++i == end);
}

const char HSET[] = 
    "x\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "y\t456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "filename with spaces\t0\t5e810a94c86ff057849bfa992bd176d8f743d160\n";

SCOPE_TEST(iterateHashset) {
  const std::tuple<std::string, size_t, sha1_t> exp[] = {
    { "x", 123, to_bytes<20>("1eb328edc1794050fa64c6c62d6656d5c6b1b6b2") },
    { "y", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { "filename with spaces", 0, to_bytes<20>("5e810a94c86ff057849bfa992bd176d8f743d160") }
  };

  HashsetIterator i(HSET, HSET + std::strlen(HSET));
  const HashsetIterator iend;  

  SCOPE_ASSERT(i != iend);
  SCOPE_ASSERT_EQUAL(*i, exp[0]);
  SCOPE_ASSERT(i != iend);
  SCOPE_ASSERT_EQUAL(*++i, exp[1]);
  SCOPE_ASSERT(i != iend);
  SCOPE_ASSERT_EQUAL(*++i, exp[2]);
  SCOPE_ASSERT(++i == iend);
}

SCOPE_TEST(loadHashset) {
  const char HSET[] = 
    "x\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "y\t456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "filename with spaces\t0\t5e810a94c86ff057849bfa992bd176d8f743d160\n";
  
  const std::vector<std::pair<size_t, sha1_t>> exp = {
    { 0, to_bytes<20>("5e810a94c86ff057849bfa992bd176d8f743d160") },
    { 123, to_bytes<20>("1eb328edc1794050fa64c6c62d6656d5c6b1b6b2") },
    { 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3")}
  };

  const SFHASH_FileMatcher m{load_hashset(HSET, HSET + std::strlen(HSET))};

  SCOPE_ASSERT_EQUAL(m.table, exp);
}

SCOPE_TEST(has_size) {
  const char HSET[] = 
    "x\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "y\t456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "filename with spaces\t0\t5e810a94c86ff057849bfa992bd176d8f743d160\n";

  auto m = make_unique_del(
    sfhash_create_matcher(HSET, HSET + std::strlen(HSET), nullptr),
    sfhash_destroy_matcher
  );

  SCOPE_ASSERT(!sfhash_matcher_has_size(m.get(), 122));
  SCOPE_ASSERT(sfhash_matcher_has_size(m.get(), 123));
  SCOPE_ASSERT(!sfhash_matcher_has_size(m.get(), 124));
}

SCOPE_TEST(has_hash) {
  const sha1_t hashes[] = {
    to_bytes<20>("5e810a94c86ff057849bfa992bd176d8f743d160"),
    to_bytes<20>("1eb328edc1794050fa64c6c62d6656d5c6b1b6b2"),
    to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3")
  };

  auto m = make_unique_del(
    sfhash_create_matcher(HSET, HSET + std::strlen(HSET), nullptr),
    sfhash_destroy_matcher
  );

  SCOPE_ASSERT(!sfhash_matcher_has_hash(m.get(), 122, hashes[0].data()));
  SCOPE_ASSERT(!sfhash_matcher_has_hash(m.get(), 123, hashes[0].data()));
  SCOPE_ASSERT(sfhash_matcher_has_hash(m.get(), 123, hashes[1].data()));
  SCOPE_ASSERT(!sfhash_matcher_has_hash(m.get(), 124, hashes[0].data()));
}

SCOPE_TEST(has_filename) {
  auto m = make_unique_del(
    sfhash_create_matcher(HSET, HSET + std::strlen(HSET), nullptr),
    sfhash_destroy_matcher
  );

  SCOPE_ASSERT(sfhash_matcher_has_filename(m.get(), "xyzzy"));
  SCOPE_ASSERT(sfhash_matcher_has_filename(m.get(), "123x"));
  SCOPE_ASSERT(!sfhash_matcher_has_filename(m.get(), "filename with space"));
}
