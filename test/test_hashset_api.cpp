#include <catch2/catch_test_macros.hpp>

#include "hex.h"
#include "util.h"

#include "helper.h"

#include "hasher/hashset.h"

#include <array>
#include <utility>
#include <vector>

/*
load_hashset(const char* hsetfile) {
  const auto f = read_file("test/test.hset");
  const auto beg = f.data();
  const auto end = beg + f.size();

  SFHASH_Error* err = nullptr;

  return std::make_tuple(
    std::move(f),
    make_unique_del(
      sfhash_load_hashset(beg, end, &err),
      sfhash_destroy_hashset
    )
    err
  );
}
*/

TEST_CASE("load_hashset") {
  const auto f = read_file("test/test.hset");
  const auto beg = f.data();
  const auto end = beg + f.size();

  SFHASH_Error* err = nullptr;

  auto hset = make_unique_del(
    sfhash_load_hashset(beg, end, &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);

  if (err) {
    // there shouldn't be an error, but if there is the message must be nonnull 
    REQUIRE(err->message);
    FAIL(err->message);
  }

  CHECK(hset);
}

TEST_CASE("load_hashset_bad") {
  SFHASH_Error* err = nullptr;

  auto hset = make_unique_del(
    sfhash_load_hashset(nullptr, nullptr, &err),
    sfhash_destroy_hashset
  );

  REQUIRE(err);
  REQUIRE(err->message);
}

TEST_CASE("hashset_index_for_type") {
  const auto f = read_file("test/test.hset");
  const auto beg = f.data();
  const auto end = beg + f.size();

  SFHASH_Error* err = nullptr;

  auto hset = make_unique_del(
    sfhash_load_hashset(beg, end, &err),
    sfhash_destroy_hashset
  );

  REQUIRE(!err);
  REQUIRE(hset);

  CHECK(sfhash_hashset_index_for_type(hset.get(), SFHASH_MD5) == 0);
  CHECK(sfhash_hashset_index_for_type(hset.get(), SFHASH_SHA_1) == 1);
  CHECK(sfhash_hashset_index_for_type(hset.get(), SFHASH_SIZE) == 2);
  CHECK(sfhash_hashset_index_for_type(hset.get(), SFHASH_OTHER) == -1);
}

template <class Tests>
void do_lookups(
  const SFHASH_Hashset* hset,
  SFHASH_HashsetType htype,
  const Tests& tests
) {
  const auto tidx = sfhash_hashset_index_for_type(hset, htype);
  REQUIRE(tidx != -1);

  for (const auto [hash, exp]: tests) { 
    CHECK(sfhash_hashset_lookup(hset, tidx, hash.data()) == exp);
  }
} 

TEST_CASE("hashset_lookup") {
  const auto f = read_file("test/test.hset");
  const auto beg = f.data();
  const auto end = beg + f.size();

  SFHASH_Error* err = nullptr;

  auto hset = make_unique_del(
    sfhash_load_hashset(beg, end, &err),
    sfhash_destroy_hashset
  );

  REQUIRE(!err);
  REQUIRE(hset);

  // lookup some MD5s

  const std::vector<std::pair<std::array<uint8_t,16>, bool>> tests_16{
    { to_bytes<16>("00000000000000000000000000000000"), false },
    { to_bytes<16>("deadbeefdeadbeefdeadbeefdeadbeef"), false },
    { to_bytes<16>("ffffffffffffffffffffffffffffffff"), false }
  };

  do_lookups(hset.get(), SFHASH_MD5, tests_16);

  // lookup some SHA1s

  const std::vector<std::pair<std::array<uint8_t,20>, bool>> tests_20{
    { to_bytes<20>("0000000000000000000000000000000000000000"), false },
    { to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"), false },
    { to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"), false }
  };
do_lookups(hset.get(), SFHASH_SHA_1, tests_20);

  // TODO: lookup with bad hset ptr?
  // TODO: lookup with bad hash type index?
}

template <class Tests>
void do_record_lookups(
  const SFHASH_Hashset* hset,
  const Tests& tests
) {
  const auto tidx = sfhash_hashset_index_for_type(hset, htype);
  REQUIRE(tidx != -1);

  for (const auto [ , ]: tests) { 

// HERE
    const auto r = sfhash_hashset_record_lookup(hset, tidx, hash.get()); 
  }
}

TEST_CASE("hashset_record_lookup") {
  const auto f = read_file("test/test.hset");
  const auto beg = f.data();
  const auto end = beg + f.size();

  SFHASH_Error* err = nullptr;

  auto hset = make_unique_del(
    sfhash_load_hashset(beg, end, &err),
    sfhash_destroy_hashset
  );

  REQUIRE(!err);
  REQUIRE(hset);




}
