#include <catch2/catch_test_macros.hpp>

#include "hex.h"
#include "util.h"

#include "helper.h"

#include "hasher/hashset.h"
#include "hashset/basic_ls.h"
#include "hashset/hset.h"
#include "hashset/hset_encoder.h"
#include "hashset/lookupstrategy.h"

#include <array>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <map>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

TEST_CASE("load_hashset_good") {
  const auto f = read_file("test/good.hset");
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

  CHECK(sfhash_hashset_name(hset.get()) == std::string("Test Name"));
  CHECK(sfhash_hashset_description(hset.get()) == std::string("Test Description"));
  CHECK(sfhash_hashset_timestamp(hset.get()) == std::string("2023-01-09T17:02:18Z"));

  const uint8_t hash[] = {
    0x2e, 0x40, 0x7e, 0x9e, 0x82, 0xdc, 0xd6, 0x06,
    0xe9, 0xed, 0xb1, 0x06, 0x2d, 0xbf, 0xcd, 0x1b,
    0x32, 0xa7, 0x5a, 0xcf, 0xe5, 0xc0, 0xd2, 0xfd,
    0xd9, 0x03, 0xa3, 0x2e, 0xe2, 0xaf, 0x77, 0x2a
  };
  CHECK(!std::memcmp(sfhash_hashset_sha2_256(hset.get()), hash, std::size(hash)));

  {
    // before first element in hashset
    const auto h = to_bytes<20>("0053e9b602c2fa8473262b590f6d24a406ae1cc2");
    CHECK(!sfhash_hashset_lookup(hset.get(), 0, h.data()));
  }

  {
    // first element in hashset
    const auto h = to_bytes<20>("0053e9b602c2fa8473262b590f6d24a406ae1cc3");
    CHECK(sfhash_hashset_lookup(hset.get(), 0, h.data()));
  }

  {
    const auto h = to_bytes<20>("286ba1181663193d119d7ca18331395cd451de91");
    CHECK(sfhash_hashset_lookup(hset.get(), 0, h.data()));
  }

  {
    const auto h = to_bytes<20>("bc658126e1443d6455287378e4c273b08f947d3c");
    CHECK(sfhash_hashset_lookup(hset.get(), 0, h.data()));
  }

  {
    // not in hashset
    const auto h = to_bytes<20>("baaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaad");
    CHECK(!sfhash_hashset_lookup(hset.get(), 0, h.data()));
  }

  {
    // last element in hashset
    const auto h = to_bytes<20>("ff36a8ea9b657f9c068d91a67195dd0764fd75ff");
    CHECK(sfhash_hashset_lookup(hset.get(), 0, h.data()));
  }

  {
    // after last element in hashset
    const auto h = to_bytes<20>("ff36a8ea9b657f9c068d91a67195dd0764fd7600");
    CHECK(!sfhash_hashset_lookup(hset.get(), 0, h.data()));
  }
}

TEST_CASE("load_hashset_nullptr") {
  SFHASH_Error* err = nullptr;

  const auto hset = make_unique_del(
    sfhash_load_hashset(nullptr, nullptr, &err),
    sfhash_destroy_hashset
  );

  CHECK(!hset);
  REQUIRE(err);
  REQUIRE(err->message);
}

TEST_CASE("load_hashset_bad") {
  const char bogus[] = "12345";

  SFHASH_Error* err = nullptr;

  const auto hset = make_unique_del(
    sfhash_load_hashset(bogus, bogus + sizeof(bogus), &err),
    sfhash_destroy_hashset
  );

  CHECK(!hset);
  REQUIRE(err);
  REQUIRE(err->message);
}

// TODO: more parsing tests

TEST_CASE("hashset_index_for_type") {
  SFHASH_Hashset hset;

  hset.holder.hsets.emplace_back(
    HashsetHeader{ SFHASH_SIZE, "size", 8, 0 },
    HashsetHint{},
    ConstHashsetData{},
    std::unique_ptr<LookupStrategy>(),
    ConstRecordIndex{}
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ SFHASH_MD5, "MD5", 16, 0 },
    HashsetHint{},
    ConstHashsetData{},
    std::unique_ptr<LookupStrategy>(),
    ConstRecordIndex{}
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ SFHASH_SHA_1, "SHA-1", 20, 0 },
    HashsetHint{},
    ConstHashsetData{},
    std::unique_ptr<LookupStrategy>(),
    ConstRecordIndex{}
  );

  CHECK(sfhash_hashset_index_for_type(&hset, SFHASH_SIZE) == 0);
  CHECK(sfhash_hashset_index_for_type(&hset, SFHASH_MD5) == 1);
  CHECK(sfhash_hashset_index_for_type(&hset, SFHASH_SHA_1) == 2);
  CHECK(sfhash_hashset_index_for_type(&hset, SFHASH_SHA_3_224) == -1);
}

template <class Tests>
void do_lookups(
  const SFHASH_Hashset* hset,
  SFHASH_HashAlgorithm htype,
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
  std::array md5s{
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

  std::array sha1s{
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
    HashsetHeader{ SFHASH_MD5, "md5", 16, 0 },
    HashsetHint{},
    ConstHashsetData{ md5s.begin(),  md5s.end() },
    std::unique_ptr<LookupStrategy>(new BasicLookupStrategy<16>(md5s.begin(), md5s.end())),
    ConstRecordIndex{}
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ SFHASH_SHA_1, "sha1", 20, 0 },
    HashsetHint{},
    ConstHashsetData{ sha1s.begin(), sha1s.end() },
    std::unique_ptr<LookupStrategy>(new BasicLookupStrategy<20>(sha1s.begin(), sha1s.end())),
    ConstRecordIndex{}
  );

  // lookup some MD5s

  std::vector<std::pair<std::array<uint8_t, 16>, bool>> tests_16{
    { to_bytes<16>("00000000000000000000000000000000"), false },
    { to_bytes<16>("deadbeefdeadbeefdeadbeefdeadbeef"), false },
    { to_bytes<16>("ffffffffffffffffffffffffffffffff"), false }
  };

  for (const auto& h: md5s) {
    tests_16.emplace_back(h, true);
  }

  do_lookups(&hset, SFHASH_MD5, tests_16);

  // lookup some SHA1s

  std::vector<std::pair<std::array<uint8_t, 20>, bool>> tests_20{
    { to_bytes<20>("0000000000000000000000000000000000000000"), false },
    { to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"), false },
    { to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"), false }
  };

  for (const auto& h: sha1s) {
    tests_20.emplace_back(h, true);
  }

  do_lookups(&hset, SFHASH_SHA_1, tests_20);
}

// TODO: lookup with bad hset ptr? (Should we guard against this?)
// TODO: lookup with bad hash type index? (Should we guard against this?)

TEST_CASE("hashset_record_field_index_for_type") {
  SFHASH_Hashset hset;

  hset.holder.rhdr.fields.emplace_back(SFHASH_SIZE, "size", 8);
  hset.holder.rhdr.fields.emplace_back(SFHASH_MD5, "MD5", 16);
  hset.holder.rhdr.fields.emplace_back(SFHASH_SHA_1, "SHA-1", 20);

  CHECK(sfhash_hashset_record_field_index_for_type(&hset, SFHASH_SIZE) == 0);
  CHECK(sfhash_hashset_record_field_index_for_type(&hset, SFHASH_MD5) == 9);
  CHECK(sfhash_hashset_record_field_index_for_type(&hset, SFHASH_SHA_1) == 26);
  CHECK(sfhash_hashset_record_field_index_for_type(&hset, SFHASH_BLAKE3) == -1);
}

TEST_CASE("hashset_lookup_bulk") {
  // create a test hset
  std::array sha1s{
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
    HashsetHeader{ SFHASH_SHA_1, "sha1", 20, 0 },
    HashsetHint{},
    ConstHashsetData{ sha1s.begin(), sha1s.end() },
    std::unique_ptr<LookupStrategy>(new BasicLookupStrategy<20>(sha1s.begin(), sha1s.end())),
    ConstRecordIndex{}
  );

  // lookup some SHA1s

  std::vector<std::array<uint8_t, 20>> lookup{
    to_bytes<20>("0000000000000000000000000000000000000000"),
    to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"),
    to_bytes<20>("6007cca8643961ed5f374d2dbf0394dc88110cdb"),
    to_bytes<20>("1127ceb2c2d789c1d7615b12082ca30222f3c612")
  };

  std::vector<uint8_t> results(lookup.size());

  sfhash_hashset_lookup_bulk(
    &hset,
    0,
    lookup.data(),
    lookup.size(),
    reinterpret_cast<bool*>(results.data())
  );

  const std::vector<uint8_t> exp{ false, false, false, true, true};

  CHECK(results == exp);
}

TEST_CASE("hashset_record_field") {
  uint8_t rec[1 + 16 + 1 + 20 + 1 + 8];
  rec[0] = 1;
  from_hex(rec + 1, "081d3d40b257d8bbc5858345ad186beb", 16);
  rec[17] = 1;
  from_hex(rec + 18, "fad37e52be19b7a6ea321b848f2d6de4b75efcc9", 20);
  rec[38] = 1;
  *reinterpret_cast<uint64_t*>(&rec[39]) = 42;

  const SFHASH_HashsetRecord* r = reinterpret_cast<const SFHASH_HashsetRecord*>(&rec);

  CHECK(!std::memcmp(sfhash_hashset_record_field(r, 0), &rec[0], 17));
  CHECK(!std::memcmp(sfhash_hashset_record_field(r, 17), &rec[17], 21));
  CHECK(!std::memcmp(sfhash_hashset_record_field(r, 38), &rec[38], 9));
}

constexpr std::initializer_list<SFHASH_HashAlgorithm> HASH_TYPES = {
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
  SFHASH_HashAlgorithm htype,
  const Tests& tests
) {
  const auto tidx = sfhash_hashset_index_for_type(hset, htype);
  REQUIRE(tidx != -1);

  // list out all the hash types in the hashset
  std::vector<std::pair<SFHASH_HashAlgorithm, int>> rec_offs;
  for (auto t: HASH_TYPES) {
    const auto toff = sfhash_hashset_record_field_index_for_type(hset, t);
    if (toff != -1) {
      rec_offs.emplace_back(t, toff);
    }
  }

  for (const auto& [hash, exp]: tests) {
    for (auto [i, end] = sfhash_hashset_records_lookup(hset, tidx, hash.data()); i != end; ++i) {
      const auto r = sfhash_hashset_record_for_hash(hset, tidx, i);
      for (const auto& [t, toff]: rec_offs) {
        const auto f = sfhash_hashset_record_field(r, toff);
        const auto e = exp.find(t);
        CHECK((e != exp.end() && !std::memcmp(&*e, f, HASH_LENGTH[t])));
      }
    }
  }
}

TEST_CASE("hashset_record_lookup") {
  // create a test hset
  std::array md5s{
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

  std::array sha1s{
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

  std::array<uint64_t, 10> sizes{
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9
  };

  std::array<
    std::tuple<
      std::array<uint8_t, 16>,
      std::array<uint8_t, 20>,
      uint64_t
    >, 10
  > recs;

  std::array<uint64_t, 10> md5s_r, sha1s_r, sizes_r;

  for (int i = 0; i < 10; ++i) {
    recs[i] = { md5s[i], sha1s[9-i], sizes[i] };
    md5s_r[i] = i;
    sha1s_r[i] = 9-i;
    sizes_r[i] = i;
  }

  SFHASH_Hashset hset;

  hset.holder.rhdr = {
    44,
    10,
    {
      { SFHASH_MD5,   "MD5",   16 },
      { SFHASH_SHA_1, "SHA-1", 20 },
      { SFHASH_SIZE,  "size",   8 }
    }
  };

  hset.holder.rdat = {
    reinterpret_cast<uint8_t*>(recs.begin()),
    reinterpret_cast<uint8_t*>(recs.end())
  };

  hset.holder.hsets.emplace_back(
    HashsetHeader{ SFHASH_MD5, "MD5", 16, 0 },
    HashsetHint{},
    ConstHashsetData{ md5s.begin(), md5s.end() },
    std::unique_ptr<LookupStrategy>(),
    ConstRecordIndex{ md5s_r.begin(), md5s_r.end() }
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ SFHASH_SHA_1, "SHA-1", 20, 0 },
    HashsetHint{},
    ConstHashsetData{ sha1s.begin(), sha1s.end() },
    std::unique_ptr<LookupStrategy>(),
    ConstRecordIndex{ sha1s_r.begin(), sha1s_r.end() }
  );

  hset.holder.hsets.emplace_back(
    HashsetHeader{ SFHASH_SIZE, "size", 8, 0 },
    HashsetHint{},
    ConstHashsetData{ sizes.begin(), sizes.end() },
    std::unique_ptr<LookupStrategy>(),
    ConstRecordIndex{ sizes_r.begin(), sizes_r.end() }
  );

  // lookup records for some MD5s

  std::vector<
    std::pair<
      std::array<uint8_t, 16>,
      std::map<
        SFHASH_HashAlgorithm,
        std::variant<
          std::array<uint8_t, 16>,
          std::array<uint8_t, 20>,
          uint64_t
        >
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

  for (int i = 0; i < 10; ++i) {
    tests_16.emplace_back(
      md5s[i],
      std::map<SFHASH_HashAlgorithm,
        std::variant<
          std::array<uint8_t, 16>,
          std::array<uint8_t, 20>,
          uint64_t
        >
      >{
        { SFHASH_MD5, md5s[i] },
        { SFHASH_SHA_1, sha1s[9-i] },
        { SFHASH_SIZE, sizes[i] }
      }
    );
  }

  do_record_lookups(&hset, SFHASH_MD5, tests_16);

  // lookup records for some SHA1s

  std::vector<
    std::pair<
      std::array<uint8_t, 20>,
      std::map<
        SFHASH_HashAlgorithm,
        std::variant<
          std::array<uint8_t, 16>,
          std::array<uint8_t, 20>,
          uint64_t
        >
      >
    >
  > tests_20{
    {
      to_bytes<20>("0000000000000000000000000000000000000000"),
      {}
    },
    {
      to_bytes<20>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
      {}
    },
    {
      to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"),
      {}
    }
  };

  for (int i = 0; i < 10; ++i) {
    tests_20.emplace_back(
      sha1s[i],
      std::map<SFHASH_HashAlgorithm,
        std::variant<
          std::array<uint8_t, 16>,
          std::array<uint8_t, 20>,
          uint64_t
        >
      >{
        { SFHASH_MD5, md5s[9-i] },
        { SFHASH_SHA_1, sha1s[i] },
        { SFHASH_SIZE, sizes[9-i] }
      }
    );
  }

  do_record_lookups(&hset, SFHASH_SHA_1, tests_20);
}

TEST_CASE("hashset_builder_open_overlong_name") {
  const std::string longname(65536, 'x');
  const SFHASH_HashAlgorithm record_order[] = { SFHASH_MD5 };

  SFHASH_Error* err = nullptr;

  const auto hctx = make_unique_del(
    sfhash_hashset_builder_open(
      longname.c_str(),
      "123",
      record_order,
      std::size(record_order),
      true,
      true,
      "test/bogus.hset",
      "test",
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  CHECK(!hctx);
  REQUIRE(err);
}

TEST_CASE("hashset_builder_open_overlong_desc") {
  const std::string longdesc(65536, 'x');
  const SFHASH_HashAlgorithm record_order[] = { SFHASH_MD5 };

  SFHASH_Error* err = nullptr;

  const auto hctx = make_unique_del(
    sfhash_hashset_builder_open(
      "123",
      longdesc.c_str(),
      record_order,
      std::size(record_order),
      true,
      true,
      "test/bogus.hset",
      "test",
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  CHECK(!hctx);
  REQUIRE(err);
}

TEST_CASE("hashset_builder_open_no_record_types") {
  SFHASH_Error* err = nullptr;

  const auto hctx = make_unique_del(
    sfhash_hashset_builder_open(
      "123",
      "abc",
      nullptr,
      0,
      true,
      true,
      "test/bogus.hset",
      "test",
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  CHECK(!hctx);
  REQUIRE(err);
}

TEST_CASE("hashset_builder_open_duplicate_types") {
  // MD5, egg, sausage, and MD5 hasn't got much MD5 in it
  const SFHASH_HashAlgorithm record_order[] = {
    SFHASH_MD5, SFHASH_SHA_1, SFHASH_MD5, SFHASH_MD5
  };

  SFHASH_Error* err = nullptr;

  const auto hctx = make_unique_del(
    sfhash_hashset_builder_open(
      "123",
      "abc",
      record_order,
      std::size(record_order),
      true,
      true,
      "test/bogus.hset",
      "test",
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  CHECK(!hctx);
  REQUIRE(err);
}

TEST_CASE("hashset_builder_open_ok") {
  const SFHASH_HashAlgorithm record_order[] = {
    SFHASH_MD5, SFHASH_SHA_1
  };

  SFHASH_Error* err = nullptr;

  const auto hctx = make_unique_del(
    sfhash_hashset_builder_open(
      "123",
      "abc",
      record_order,
      std::size(record_order),
      true,
      true,
      "test/bogus.hset",
      "test",
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  CHECK(!err);

  if (err) {
    FAIL(err->message);
  }

  REQUIRE(hctx);

  const std::vector<RecordFieldDescriptor> exp_fields = {
    { SFHASH_MD5, "md5", 16 },
    { SFHASH_SHA_1, "sha1", 20 }
  };

  CHECK(hctx->fhdr.name == "123");
  CHECK(hctx->fhdr.desc == "abc");
  // don't check the timestamp, it will differ on each run
  CHECK(hctx->rhdr.record_length == 38);
  CHECK(hctx->rhdr.fields == exp_fields);
}

TEST_CASE("hashset_builder_setop_open_overlong_name") {
  SFHASH_Hashset l;
  SFHASH_Hashset r;

  // ensure these are set becuase we read them (though in the error case
  // don't actually use the values)
  l.holder.rhdr.record_count = 0;
  r.holder.rhdr.record_count = 0;

  const std::string longname(65536, 'x');

  SFHASH_Error* err = nullptr;

  const auto tests = {
    std::make_pair(sfhash_hashset_builder_union_open, "union"),
    std::make_pair(sfhash_hashset_builder_intersect_open, "intersection"),
    std::make_pair(sfhash_hashset_builder_subtract_open, "difference")
  };

  for (const auto& [func, name]: tests) {
    DYNAMIC_SECTION(name) {
      const auto hctx = make_unique_del(
        func(
          &l,
          &r,
          longname.c_str(),
          "123",
          true,
          true,
          "test/bogus.hset",
          "test",
          &err
        ),
        sfhash_hashset_builder_destroy
      );

      CHECK(!hctx);
      REQUIRE(err);

      sfhash_free_error(err);
      err = nullptr;
    }
  }
}

TEST_CASE("hashset_builder_setop_open_overlong_desc") {
  SFHASH_Hashset l;
  SFHASH_Hashset r;

  // ensure these are set becuase we read them (though in the error case
  // don't actually use the values)
  l.holder.rhdr.record_count = 0;
  r.holder.rhdr.record_count = 0;

  const std::string longdesc(65536, 'x');

  SFHASH_Error* err = nullptr;

  const auto tests = {
    std::make_pair(sfhash_hashset_builder_union_open, "union"),
    std::make_pair(sfhash_hashset_builder_intersect_open, "intersection"),
    std::make_pair(sfhash_hashset_builder_subtract_open, "difference")
  };

  for (const auto& [func, name]: tests) {
    DYNAMIC_SECTION(name) {
      const auto hctx = make_unique_del(
        func(
          &l,
          &r,
          "123",
          longdesc.c_str(),
          true,
          true,
          "test/bogus.hset",
          "test",
          &err
        ),
        sfhash_hashset_builder_destroy
      );

      CHECK(!hctx);
      REQUIRE(err);

      sfhash_free_error(err);
      err = nullptr;
    }
  }
}

TEST_CASE("hashset_builder_setop_open_field_mismatch") {
  SFHASH_Hashset l;
  l.holder.rhdr = RecordHeader{ 17, 1, { {SFHASH_MD5, "MD5", 16} } };

  SFHASH_Hashset r;
  r.holder.rhdr = RecordHeader{ 17, 1, { {SFHASH_SHA_1, "SHA-1", 20} } };

  SFHASH_Error* err = nullptr;

  const auto tests = {
    std::make_pair(sfhash_hashset_builder_union_open, "union"),
    std::make_pair(sfhash_hashset_builder_intersect_open, "intersection"),
    std::make_pair(sfhash_hashset_builder_subtract_open, "difference")
  };

  for (const auto& [func, name]: tests) {
    DYNAMIC_SECTION(name) {
      const auto hctx = make_unique_del(
        func(
          &l,
          &r,
          "123",
          "abc",
          true,
          true,
          "test/bogus.hset",
          "test",
          &err
        ),
        sfhash_hashset_builder_destroy
      );

      CHECK(!hctx);
      REQUIRE(err);

      sfhash_free_error(err);
      err = nullptr;
    }
  }
}
