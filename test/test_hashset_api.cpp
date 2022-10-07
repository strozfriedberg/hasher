#include <catch2/catch_test_macros.hpp>

#include "hex.h"
#include "util.h"

#include "helper.h"

#include "hasher/hashset.h"
#include "hashset/basic_ls.h"
#include "hashset/hset.h"
#include "hashset/lookupstrategy.h"

#include <array>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <utility>
#include <vector>

TEST_CASE("load_hashset_good") {
  const auto f = read_file("test/test.hset");
  const auto beg = f.data();
  const auto end = beg + f.size();

  SFHASH_Error* err = nullptr;

  const auto hset = make_unique_del(
    sfhash_load_hashset(beg, end, &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);

  if (err) {
    FAIL(err->message);
  }

  CHECK(hset);
}

TEST_CASE("load_hashset_bad") {
  SFHASH_Error* err = nullptr;

  const auto hset = make_unique_del(
    sfhash_load_hashset(nullptr, nullptr, &err),
    sfhash_destroy_hashset
  );

  REQUIRE(err);
  REQUIRE(err->message);
}

// TODO: more parsing tests

TEST_CASE("hashset_index_for_type") {
  SFHASH_Hashset hset;

  hset.holder.hsets.emplace_back(
    HashsetHeader{ X_SFHASH_SIZE, "size", 8, 0 },
    HashsetHint{},
    HashsetData{},
    std::unique_ptr<LookupStrategy>(),
    RecordIndex{}
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ X_SFHASH_MD5, "MD5", 16, 0 },
    HashsetHint{},
    HashsetData{},
    std::unique_ptr<LookupStrategy>(),
    RecordIndex{}
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ X_SFHASH_SHA_1, "SHA-1", 20, 0 },
    HashsetHint{},
    HashsetData{},
    std::unique_ptr<LookupStrategy>(),
    RecordIndex{}
  );

  CHECK(sfhash_hashset_index_for_type(&hset, X_SFHASH_SIZE) == 0);
  CHECK(sfhash_hashset_index_for_type(&hset, X_SFHASH_MD5) == 1);
  CHECK(sfhash_hashset_index_for_type(&hset, X_SFHASH_SHA_1) == 2);
  CHECK(sfhash_hashset_index_for_type(&hset, X_SFHASH_OTHER) == -1);
}

template <class Tests>
void do_lookups(
  const SFHASH_Hashset* hset,
  SFHASH_HashsetType htype,
  const Tests& tests
) {
  const auto tidx = sfhash_hashset_index_for_type(hset, htype);
  REQUIRE(tidx != -1);

  for (const auto& [hash, exp]: tests) {
    CHECK(sfhash_hashset_lookup(hset, tidx, hash.data()) == exp);
  }
}

TEST_CASE("hashset_lookup") {
  // create a test hset
  const std::array md5s{
    to_bytes<16>("081d3d40b257d8bbc5858345ad186beb"),
    to_bytes<16>("19875d9651a319fdb8f7332b660c432d"),
    to_bytes<16>("297da3f7f9c7a38fcb8872193cf3b609"),
    to_bytes<16>("56f8af1ba509b13c01a0eb64c015bcd9"),
    to_bytes<16>("6a9ffae1487ee7c347b188ecfcdf1bd3"),
    to_bytes<16>("7932bda72aa49ba324e51a5410fd569f"),
    to_bytes<16>("857cc4681e7a952cbd26042140f5a2cc"),
    to_bytes<16>("a4b262726db358a71d80ced2cc871b45"),
    to_bytes<16>("abdba04b7527c095bb79e19db8e1de13"),
    to_bytes<16>("eb6fe7367307473c86c3438744c3b1db")
  };

  const std::array sha1s{
    to_bytes<20>("0af8e028c7048ad772ddec2200ec7e0e4d58b0c3"),
    to_bytes<20>("1127ceb2c2d789c1d7615b12082ca30222f3c612"),
    to_bytes<20>("3e909896b309492e00444212bb2b270b5809a0cf"),
    to_bytes<20>("5cb3a026273fd180a9cfc32bfe3da8730e4bd192"),
    to_bytes<20>("6007cca8643961ed5f374d2dbf0394dc88110cdb"),
    to_bytes<20>("78e7f1736d31d8b5b1beb41e2e41769754d3cf3f"),
    to_bytes<20>("a40ea2ba2d45f9aa4d2b31adfcad0bbdb6670452"),
    to_bytes<20>("b46c74716a8b1fbf5fedc75f58c9c72b53631123"),
    to_bytes<20>("c1ec34d963283b8ca0ac899164dfbb3fc2321e38"),
    to_bytes<20>("fad37e52be19b7a6ea321b848f2d6de4b75efcc9")
  };

  SFHASH_Hashset hset;

  hset.holder.hsets.emplace_back(
    HashsetHeader{ X_SFHASH_MD5, "md5", 16, 0 },
    HashsetHint{},
    HashsetData{ md5s.begin(),  md5s.end() },
    std::unique_ptr<LookupStrategy>(new BasicLookupStrategy<16>(md5s.begin(), md5s.end())),
    RecordIndex{}
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ X_SFHASH_SHA_1, "sha1", 20, 0 },
    HashsetHint{},
    HashsetData{ sha1s.begin(), sha1s.end() },
    std::unique_ptr<LookupStrategy>(new BasicLookupStrategy<20>(sha1s.begin(), sha1s.end())),
    RecordIndex{}
  );

  // lookup some MD5s

  std::vector<std::pair<std::array<uint8_t,16>, bool>> tests_16{
    { to_bytes<16>("00000000000000000000000000000000"), false },
    { to_bytes<16>("deadbeefdeadbeefdeadbeefdeadbeef"), false },
    { to_bytes<16>("ffffffffffffffffffffffffffffffff"), false }
  };

  for (const auto& h: md5s) {
    tests_16.emplace_back(h, true);
  }

  do_lookups(&hset, X_SFHASH_MD5, tests_16);

  // lookup some SHA1s

  std::vector<std::pair<std::array<uint8_t,20>, bool>> tests_20{
    { to_bytes<20>("0000000000000000000000000000000000000000"), false },
    { to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"), false },
    { to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"), false }
  };

  for (const auto& h: sha1s) {
    tests_20.emplace_back(h, true);
  }

  do_lookups(&hset, X_SFHASH_SHA_1, tests_20);
}

// TODO: lookup with bad hset ptr?
// TODO: lookup with bad hash type index?

/*
constexpr std::initializer_list<SFHASH_HashsetType> HASH_TYPES = {
  SFHASH_SIZE,
  SFHASH_MD5,
  SFHASH_SHA_1,
  SFHASH_SHA_2_224,
  SFHASH_SHA_2_256,
  SFHASH_SHA_2_384,
  SFHASH_SHA_2_512,
  SFHASH_SHA_3_224,
  SFHASH_SHA_3_256,
  SFHASH_SHA_3_384,
  SFHASH_SHA_3_512,
  SFHASH_BLAKE3,
//  SFHASH_FUZZY,
  SFHASH_ENTROPY,
//  SFHASH_QUICK_MD5
};

constexpr size_t HASH_LENGTH[] = {
  8,
  16,
  20,
  28,
  32,
  48,
  64,
  28,
  32,
  48,
  64,
  20,
  8
};

template <class Tests>
void do_record_lookups(
  const SFHASH_Hashset* hset,
  SFHASH_HashsetType htype,
  const Tests& tests
) {
  const auto tidx = sfhash_hashset_index_for_type(hset, htype);
  REQUIRE(tidx != -1);

  for (const auto [hash, exp]: tests) {
    for (auto [i, end] = sfhash_hashset_records_lookup(hset, tidx, hash); i != end; ++i) {
      const SFHASH_HashsetRecord* r = sfhash_hashset_record_for_hash(hset, tidx, i);
      for (auto t: HASH_TYPES) {
        const void* f = sfhash_hashset_record_field(r, t);

// HERE
        if (std::get<t>exp[t]) {
          CHECK(std::memcmp(exp[t], f, HASH_LENGTH[t]) == 0);
        }
        else {
          // no expected value, should both be null
          CHECK(!f);
        }
      }
    }
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

  // lookup records for some MD5s

  const std::vector<
    std::pair<
      std::array<uint8_t,16>,
      std::tuple<
        std::optional<uint64_t>,
        std::optional<std::array<uint8_t,16>>,
        std::optional<std::array<uint8_t,20>>
      >
    >
  > tests_16{
    {
      to_bytes<16>("00000000000000000000000000000000"),
      {}
    },
    {
      to_bytes<16>("deadbeefdeadbeefdeadbeefdeadbeef"),
      {}
    },
    {
      to_bytes<16>("ffffffffffffffffffffffffffffffff"),
      {}
    }
  };

  do_record_lookups(hset.get(), SFHASH_MD5, tests_16);

}
*/
