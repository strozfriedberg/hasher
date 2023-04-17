#include <catch2/catch_test_macros.hpp>

#include "helper.h"

#include "hex.h"
#include "util.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_encoder.h"

#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

TEST_CASE("hset_round_trip") {
  const std::string hsetfile = "test/sha1.hset";

  const auto f = read_file("test/sha1");
  const std::string s(f.begin(), f.end());

  std::istringstream in(s);
  std::vector<uint8_t> out;

  const std::vector<SFHASH_HashAlgorithm> htypes{ SFHASH_SHA_1 };
  const auto conv = make_text_converters(htypes);

  write_hset(
    in,
    htypes,
    conv,
    "Test! Of! Hashset!",
    "I'd like to buy a vowel.",
    hsetfile,
    "test",
    true,
    true
  );

  const auto hsf = read_file(hsetfile);
  const auto beg = hsf.data();
  const auto end = beg + hsf.size();

  SFHASH_Error* err = nullptr;

  auto hset = make_unique_del(
    sfhash_load_hashset(beg, end, &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  REQUIRE(hset);

  const auto tidx = sfhash_hashset_index_for_type(hset.get(), SFHASH_SHA_1);
  REQUIRE(tidx == 0);

  in.str(s);

  std::string line;
  while (in) {
    std::getline(in, line);

    if (line.empty()) {
      continue;
    }

    const auto hash = to_bytes<20>(line.c_str());
    CHECK(sfhash_hashset_lookup(hset.get(), tidx, hash.data()));
  }
}

auto read_hset(
  const std::string& inpath,
  const std::vector<SFHASH_HashAlgorithm>& hash_types,
  const std::string& outpath)
{
  {
    std::ifstream in(inpath);

    write_hset(
      in,
      hash_types,
      make_text_converters(hash_types),
      "Test! Of! Hashset!",
      "Do not adjust your hashset. This is only a test.",
      outpath,
      "test",
      true,
      true
    );
  }

  auto f = read_file(outpath);

  SFHASH_Error* err = nullptr;

  auto hset = make_unique_del(
    sfhash_load_hashset(f.data(), f.data() + f.size(), &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  REQUIRE(hset);

  return std::make_pair(std::move(f), std::move(hset));
}

TEST_CASE("hset_union_round_trip") {
  auto [bufa, ha] = read_hset(
    "test/md5_sha1_a",
    { SFHASH_MD5, SFHASH_SHA_1 },
    "test/md5_sha1_a.hset"
  );
  auto [bufb, hb] = read_hset(
    "test/md5_sha1_b",
    { SFHASH_MD5, SFHASH_SHA_1 },
    "test/md5_sha1_b.hset"
  );

  // a union b = c

  SFHASH_Error* err = nullptr;

  auto hctx = make_unique_del(
    sfhash_hashset_builder_union_open(
      ha.get(),
      hb.get(),
      "c",
      "a union b",
      true,
      true,
      "test/md5_sha1_aub.hset",
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

  sfhash_hashset_builder_write(hctx.get(), &err);

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  hctx.reset();

  const auto bufc = read_file("test/md5_sha1_aub.hset");

  auto hc = make_unique_del(
    sfhash_load_hashset(bufc.data(), bufc.data() + bufc.size(), &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  REQUIRE(ha->holder.rhdr.record_length == hb->holder.rhdr.record_length);
  REQUIRE(hb->holder.rhdr.record_length == hc->holder.rhdr.record_length);

  const size_t rlen = hc->holder.rhdr.record_length;

  const SFHASH_HashsetRecord* ar = reinterpret_cast<const SFHASH_HashsetRecord*>(ha->holder.rdat.beg);
  const SFHASH_HashsetRecord* br = reinterpret_cast<const SFHASH_HashsetRecord*>(hb->holder.rdat.beg);
  const SFHASH_HashsetRecord* cr = reinterpret_cast<const SFHASH_HashsetRecord*>(hc->holder.rdat.beg);

  const SFHASH_HashsetRecord* ae = reinterpret_cast<const SFHASH_HashsetRecord*>(ha->holder.rdat.end);
  const SFHASH_HashsetRecord* be = reinterpret_cast<const SFHASH_HashsetRecord*>(hb->holder.rdat.end);
  const SFHASH_HashsetRecord* ce = reinterpret_cast<const SFHASH_HashsetRecord*>(hc->holder.rdat.end);

  // we're not already past the end
  REQUIRE(ar <= ae);
  REQUIRE(br <= be);
  REQUIRE(cr <= ce);

  while (cr < ce) {
    const int ca_cmp = ar < ae ? std::memcmp(cr, ar, rlen) : -1;
    const int cb_cmp = br < be ? std::memcmp(cr, br, rlen) : -1;

    // the union must not go ahead of either operand; because each record
    // sequence is sorted, if the union gets ahead of an operand, the left
    // behind records from the operand will not appear in the union
    REQUIRE(ca_cmp <= 0);
    REQUIRE(cb_cmp <= 0);

    // at least one of the operands contributed the record to the union
    REQUIRE((ca_cmp == 0 || cb_cmp == 0));

    if (ca_cmp == 0) {
      // cr == ar, advance ar
      ar += rlen;
    }

    if (cb_cmp == 0) {
      // cr == br, advance br
      br += rlen;
    }

    cr += rlen;
  }

  // all records are exhausted
  REQUIRE(ar == ae);
  REQUIRE(br == be);
  REQUIRE(cr == ce);
}

TEST_CASE("hset_intersection_round_trip") {
  auto [bufa, ha] = read_hset(
    "test/md5_sha1_a",
    { SFHASH_MD5, SFHASH_SHA_1 },
    "test/md5_sha1_a.hset"
  );
  auto [bufb, hb] = read_hset(
    "test/md5_sha1_b",
    { SFHASH_MD5, SFHASH_SHA_1 },
    "test/md5_sha1_b.hset"
  );

  // a intersect b = c

  SFHASH_Error* err = nullptr;

  auto hctx = make_unique_del(
    sfhash_hashset_builder_intersect_open(
      ha.get(),
      hb.get(),
      "c",
      "a intersect b",
      true,
      true,
      "test/md5_sha1_anb.hset",
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

  sfhash_hashset_builder_write(hctx.get(), &err);

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  hctx.reset();

  const auto bufc = read_file("test/md5_sha1_anb.hset");

  auto hc = make_unique_del(
    sfhash_load_hashset(bufc.data(), bufc.data() + bufc.size(), &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  REQUIRE(ha->holder.rhdr.record_length == hb->holder.rhdr.record_length);
  REQUIRE(hb->holder.rhdr.record_length == hc->holder.rhdr.record_length);

  const size_t rlen = hc->holder.rhdr.record_length;

  const SFHASH_HashsetRecord* ar = reinterpret_cast<const SFHASH_HashsetRecord*>(ha->holder.rdat.beg);
  const SFHASH_HashsetRecord* br = reinterpret_cast<const SFHASH_HashsetRecord*>(hb->holder.rdat.beg);
  const SFHASH_HashsetRecord* cr = reinterpret_cast<const SFHASH_HashsetRecord*>(hc->holder.rdat.beg);

  const SFHASH_HashsetRecord* ae = reinterpret_cast<const SFHASH_HashsetRecord*>(ha->holder.rdat.end);
  const SFHASH_HashsetRecord* be = reinterpret_cast<const SFHASH_HashsetRecord*>(hb->holder.rdat.end);
  const SFHASH_HashsetRecord* ce = reinterpret_cast<const SFHASH_HashsetRecord*>(hc->holder.rdat.end);

  // we're not already past the end
  REQUIRE(ar <= ae);
  REQUIRE(br <= be);
  REQUIRE(cr <= ce);

  while (ar < ae && br < be) {
    const int ab_cmp = std::memcmp(ar, br, rlen);
    if (ab_cmp < 0) {
      // ar < br, advance ar
      ar += rlen;
    }
    else if (ab_cmp > 0) {
      // br < ar, advance br
      br += rlen;
    }
    else {
      // ar == br, check cr and advance all
      REQUIRE(cr < ce);
      REQUIRE(std::memcmp(cr, ar, rlen) == 0);

      ar += rlen;
      br += rlen;
      cr += rlen;
    }
  }

  // all records are exhausted
  REQUIRE((ar == ae || br == be));
  REQUIRE(cr == ce);
}

TEST_CASE("hset_difference_round_trip") {
  auto [bufa, ha] = read_hset(
    "test/md5_sha1_a",
    { SFHASH_MD5, SFHASH_SHA_1 },
    "test/md5_sha1_a.hset"
  );
  auto [bufb, hb] = read_hset(
    "test/md5_sha1_b",
    { SFHASH_MD5, SFHASH_SHA_1 },
    "test/md5_sha1_b.hset"
  );

  // a - b = c

  SFHASH_Error* err = nullptr;

  auto hctx = make_unique_del(
    sfhash_hashset_builder_subtract_open(
      ha.get(),
      hb.get(),
      "c",
      "a minus b",
      true,
      true,
      "test/md5_sha1_a-b.hset",
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

  sfhash_hashset_builder_write(hctx.get(), &err);

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  hctx.reset();

  const auto bufc = read_file("test/md5_sha1_a-b.hset");

  auto hc = make_unique_del(
    sfhash_load_hashset(bufc.data(), bufc.data() + bufc.size(), &err),
    sfhash_destroy_hashset
  );

  CHECK(!err);
  if (err) {
    FAIL(err->message);
  }

  REQUIRE(ha->holder.rhdr.record_length == hb->holder.rhdr.record_length);
  REQUIRE(hb->holder.rhdr.record_length == hc->holder.rhdr.record_length);

  const size_t rlen = hc->holder.rhdr.record_length;

  const SFHASH_HashsetRecord* ar = reinterpret_cast<const SFHASH_HashsetRecord*>(ha->holder.rdat.beg);
  const SFHASH_HashsetRecord* br = reinterpret_cast<const SFHASH_HashsetRecord*>(hb->holder.rdat.beg);
  const SFHASH_HashsetRecord* cr = reinterpret_cast<const SFHASH_HashsetRecord*>(hc->holder.rdat.beg);

  const SFHASH_HashsetRecord* ae = reinterpret_cast<const SFHASH_HashsetRecord*>(ha->holder.rdat.end);
  const SFHASH_HashsetRecord* be = reinterpret_cast<const SFHASH_HashsetRecord*>(hb->holder.rdat.end);
  const SFHASH_HashsetRecord* ce = reinterpret_cast<const SFHASH_HashsetRecord*>(hc->holder.rdat.end);

  // we're not already past the end
  REQUIRE(ar <= ae);
  REQUIRE(br <= be);
  REQUIRE(cr <= ce);

  while (ar < ae) {
    const int ab_cmp = br < be ? std::memcmp(ar, br, rlen) : -1;
    if (ab_cmp < 0) {
      // ar < br, check ar == cr and advance ar, cr
      REQUIRE(cr < ce);
      REQUIRE(std::memcmp(cr, ar, rlen) == 0);

      ar += rlen;
      cr += rlen;
    }
    else if (ab_cmp > 0) {
      // br < ar, advance br
      br += rlen;
    }
    else {
      // ar == br, advance both
      ar += rlen;
      br += rlen;
    }
  }

  // all records in a, c are exhausted; b doesn't matter
  REQUIRE(ar == ae);
  REQUIRE(cr == ce);
}

/*
    std::cerr << to_hex(ar, ar + rlen) << '\n'
              << to_hex(br, br + rlen) << '\n'
              << to_hex(cr, cr + rlen) << "\n\n";
*/
