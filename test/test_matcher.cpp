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

SCOPE_TEST(iterateLinesLF) {
  const char txt[] = "abc\ndef\ng\nhijk\n\nlmnop\n";
  //                  012 3456 78 90123 4 567890 1

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+4, txt+7));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+8, txt+9));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+14));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+15, txt+15));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+16, txt+21));
  SCOPE_ASSERT(++i == end);
}

SCOPE_TEST(iterateLinesLFNoTerminalEOL) {
  const char txt[] = "abc\ndef\ng\nhijk\n\nlmnop";
  //                  012 3456 78 90123 4 567890

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+4, txt+7));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+8, txt+9));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+14));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+15, txt+15));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+16, txt+21));
  SCOPE_ASSERT(++i == end);
}

SCOPE_TEST(iterateLinesCRLF) {
  const char txt[] = "abc\r\ndef\r\ng\r\nhijk\r\n\r\nlmnop\r\n";
  //                  012 3 4567 8 90 1 23456 7 8 9 012345 6 7

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+5, txt+8));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+11));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+13, txt+17));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+19, txt+19));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+21, txt+26));
  SCOPE_ASSERT(++i == end);
}

SCOPE_TEST(iterateLinesCRLFNoTerminalEOL) {
  const char txt[] = "abc\r\ndef\r\ng\r\nhijk\r\n\r\nlmnop";
  //                  012 3 4567 8 90 1 23456 7 8 9 012345

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+5, txt+8));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+11));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+13, txt+17));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+19, txt+19));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+21, txt+26));
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

  LineIterator l(HSET, HSET + std::strlen(HSET));
  const LineIterator lend(HSET + std::strlen(HSET), HSET + std::strlen(HSET));

  SCOPE_ASSERT(l != lend);
  SCOPE_ASSERT_EQUAL(parse_line(l->first, l->second), exp[0]);
  SCOPE_ASSERT(++l != lend);
  SCOPE_ASSERT_EQUAL(parse_line(l->first, l->second), exp[1]);
  SCOPE_ASSERT(++l != lend);
  SCOPE_ASSERT_EQUAL(parse_line(l->first, l->second), exp[2]);
  SCOPE_ASSERT(++l == lend);
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

  LG_Error* err = nullptr;
  auto m{load_hashset(HSET, HSET + std::strlen(HSET), &err)};

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);
  SCOPE_ASSERT_EQUAL(m->table, exp);
}

SCOPE_TEST(has_size) {
  const char HSET[] =
    "x\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "y\t456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "filename with spaces\t0\t5e810a94c86ff057849bfa992bd176d8f743d160\n";

  LG_Error* err = nullptr;

  auto m = make_unique_del(
    sfhash_create_matcher(HSET, HSET + std::strlen(HSET), &err),
    sfhash_destroy_matcher
  );

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);

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

  LG_Error* err = nullptr;

  auto m = make_unique_del(
    sfhash_create_matcher(HSET, HSET + std::strlen(HSET), &err),
    sfhash_destroy_matcher
  );

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);

  SCOPE_ASSERT(!sfhash_matcher_has_hash(m.get(), 122, hashes[0].data()));
  SCOPE_ASSERT(!sfhash_matcher_has_hash(m.get(), 123, hashes[0].data()));
  SCOPE_ASSERT(sfhash_matcher_has_hash(m.get(), 123, hashes[1].data()));
  SCOPE_ASSERT(!sfhash_matcher_has_hash(m.get(), 124, hashes[0].data()));
}

SCOPE_TEST(has_filename) {
  LG_Error* err = nullptr;

  auto m = make_unique_del(
    sfhash_create_matcher(HSET, HSET + std::strlen(HSET), &err),
    sfhash_destroy_matcher
  );

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);

  SCOPE_ASSERT(sfhash_matcher_has_filename(m.get(), "xyzzy"));
  SCOPE_ASSERT(sfhash_matcher_has_filename(m.get(), "123x"));
  SCOPE_ASSERT(!sfhash_matcher_has_filename(m.get(), "filename with space"));
}
