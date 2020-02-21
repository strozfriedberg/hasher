#include <iostream>

#include <cstring>

#include "hasher.h"
#include "hex.h"
#include "matcher.h"
#include "util.h"

/*
using matcher_table_t = std::vector<sha1_t>>;

void assert_matcher_tables_equal(const matcher_table_t& actual, const matcher_table_t& expected) {
  SCOPE_ASSERT_EQUAL(expected.size(), actual.size());
  for (uint8_t i = 0; i < actual.size(); ++i) {
    uint64_t exp_file_size = expected[i].first;
    uint64_t act_file_size = actual[i].first;
    SCOPE_ASSERT_EQUAL(exp_file_size, act_file_size);

    const std::string exp_hash = to_hex(expected[i].second);
    const std::string act_hash = to_hex(actual[i].second);
    SCOPE_ASSERT_EQUAL(exp_hash, act_hash);
  }
}
*/

template <typename T>
std::ostream& operator<<(std::ostream& o, const std::unordered_set<T>& s) {
  o << '{';
  for (const auto& t: s) {
    o << t << ", ";
  }
  o << '}';
  return o;
}

std::ostream& operator<<(std::ostream& o, const sha1_t& h) {
  return o << to_hex(h);
}

#include <scope/test.h>


const char HSET[] = "x\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
                    "y\t456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
                    "filename with spaces\t0\t5e810a94c86ff057849bfa992bd176d8f743d160\n";

const std::vector<sha1_t> EXP_HASHES = {
  to_bytes<20>("1eb328edc1794050fa64c6c62d6656d5c6b1b6b2"),
  to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3"),
  to_bytes<20>("5e810a94c86ff057849bfa992bd176d8f743d160")
};

const std::unordered_set<uint64_t> EXP_SIZES = { 0, 123, 456789 };

SCOPE_TEST(loadHashset) {
  LG_Error* err = nullptr;
  auto m{load_hashset(HSET, HSET + std::strlen(HSET), &err)};

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);

  // FIXME: SCOPE_ASSERT_EQUAL mishandles std::unordered_set
  SCOPE_ASSERT(EXP_SIZES == m->Sizes);
  SCOPE_ASSERT_EQUAL(EXP_HASHES, m->Hashes);
}

SCOPE_TEST(has_size) {
  LG_Error* err = nullptr;

  auto m = make_unique_del(sfhash_create_matcher(HSET, HSET + std::strlen(HSET), &err),
                           sfhash_destroy_matcher);

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);

  SCOPE_ASSERT(!sfhash_matcher_has_size(m.get(), 122));
  SCOPE_ASSERT(sfhash_matcher_has_size(m.get(), 123));
  SCOPE_ASSERT(!sfhash_matcher_has_size(m.get(), 124));
}

SCOPE_TEST(has_hash) {
  const sha1_t hashes[] = {
    to_bytes<20>("1eb328edc1794050fa64c6c62d6656d5c6b1b6b2"),
    to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3"),
    to_bytes<20>("5e810a94c86ff057849bfa992bd176d8f743d160")
  };

  const sha1_t not_there = to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

  LG_Error* err = nullptr;

  auto m = make_unique_del(sfhash_create_matcher(HSET, HSET + std::strlen(HSET), &err),
                           sfhash_destroy_matcher);

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);

  SCOPE_ASSERT(sfhash_matcher_has_hash(m.get(), hashes[0].data()));
  SCOPE_ASSERT(sfhash_matcher_has_hash(m.get(), hashes[1].data()));
  SCOPE_ASSERT(sfhash_matcher_has_hash(m.get(), hashes[2].data()));
  SCOPE_ASSERT(!sfhash_matcher_has_hash(m.get(), not_there.data()));
}

SCOPE_TEST(has_filename) {
  LG_Error* err = nullptr;

  auto m = make_unique_del(sfhash_create_matcher(HSET, HSET + std::strlen(HSET), &err),
                           sfhash_destroy_matcher);

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m);

  SCOPE_ASSERT(sfhash_matcher_has_filename(m.get(), "xyzzy"));
  SCOPE_ASSERT(sfhash_matcher_has_filename(m.get(), "123x"));
  SCOPE_ASSERT(!sfhash_matcher_has_filename(m.get(), "filename with space"));
}

/*
SCOPE_TEST(binaryMatcherTableRoundTrip) {
  LG_Error* err = nullptr;

  auto m1 = make_unique_del(sfhash_create_matcher(HSET, HSET + std::strlen(HSET), &err),
                            sfhash_destroy_matcher);

  SCOPE_ASSERT(!err);
  SCOPE_ASSERT(m1);

  const int msize = sfhash_matcher_size(m1.get());
  std::unique_ptr<uint8_t[]> buf(new uint8_t[msize]);
  sfhash_write_binary_matcher(m1.get(), buf.get());

  auto m2 = make_unique_del(sfhash_read_binary_matcher(buf.get(), buf.get() + msize),
                            sfhash_destroy_matcher);

  SCOPE_ASSERT(m2);
  SCOPE_ASSERT_EQUAL(EXP_SIZES, m1->Sizes);
  SCOPE_ASSERT_EQUAL(EXP_HASHES, m2->Hashes);
}
*/
