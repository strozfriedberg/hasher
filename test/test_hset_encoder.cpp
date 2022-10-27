#include "hset_encoder.h"
#include "hex.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <tuple>
#include <utility>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("size_to_u64_good") {
  const std::initializer_list<std::pair<const char*, uint64_t>> tests = {
    { "0", 0 },
    { "42", 42 },
    { "10000000", 10000000 },
    { "18446744073709551615", 0xFFFFFFFFFFFFFFFF }
  };

  uint8_t dst[8];
  for (const auto& [in, exp]: tests) {
    DYNAMIC_SECTION(in << ' ' << exp) {
      size_to_u64(dst, in, 8);
      CHECK(*reinterpret_cast<const uint64_t*>(dst) == exp);
    }
  }
}

TEST_CASE("size_to_u64_bad") {
  const auto tests = {
    "-1",                   // too small
    "18446744073709551616", // too large
    "3.7",                  // not an integer
    "Bob"                   // not a number
  };

  uint8_t dst[8];
  for (const auto& in: tests) {
    DYNAMIC_SECTION(in << " throws") {
      CHECK_THROWS(size_to_u64(dst, in, 8));
    }
  }
}

TEST_CASE("length_alignment_padding") {
  const std::initializer_list<std::tuple<uint64_t, uint64_t, size_t>> tests = {
    {    0, 4096,    0 },
    {    1, 4096, 4095 },
    { 4095, 4096,    1 },
    { 4096, 4096,    0 }
  };

  for (const auto& [pos, align, plen]: tests) {
    CHECK(length_alignment_padding(pos, align) == plen);
  }
}

TEST_CASE("write_alignment_padding") {
  const std::initializer_list<std::tuple<uint64_t, uint64_t, size_t>> tests = {
    {    0, 4096,    0 },
    {    1, 4096, 4095 },
    { 4095, 4096,    1 },
    { 4096, 4096,    0 }
  };

  char buf[4096];

  for (const auto& [pos, align, plen]: tests) {
    std::fill(std::begin(buf), std::end(buf), 0xFF);
    // Is it reporting the expected amount of padding?
    CHECK(write_alignment_padding(pos, align, buf) == plen);
    // Did it write at least the expected amount of padding?
    CHECK(std::all_of(std::begin(buf), std::begin(buf) + plen, [](char c){ return c == '\x00'; }));
    // Did it write no more than the expected amount of padding?
    CHECK(std::all_of(std::begin(buf) + plen, std::end(buf), [](char c){ return c == '\xFF'; }));
  }
}

TEST_CASE("length_magic") {
  CHECK(length_magic() == 8);
}

TEST_CASE("write_magic") {
  char buf[8];
  CHECK(write_magic(buf) == 8);
  CHECK(!std::memcmp(buf, "SetOHash", 8));
}

TEST_CASE("length_fhdr") {
  CHECK(length_fhdr("123", "4567", "890") == 68);
}

TEST_CASE("write_fhdr") {
  const uint32_t version = 2;
  const char name[] = "name";
  const char desc[] = "desc";
  const char ts[] = "2022-10-26T18:13:07Z";

  const uint8_t exp[] = {
    // chunk type
    'F', 'H', 'D', 'R',
    // chunk data length
    0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // version
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hashset name length
    0x04, 0x00,
    // hashset name
    'n', 'a', 'm', 'e',
    // hashset timestamp length
    0x14, 0x00,
    // hashset timestamp
    '2', '0', '2', '2', '-', '1', '0', '-', '2', '6', 'T', '1', '8', ':', '1', '3', ':', '0', '7', 'Z',
    // hashset description length
    0x04, 0x00,
    // hashset description
    'd', 'e', 's', 'c',
    // chunk hash
    0xDB, 0x66, 0x60, 0x21, 0x5B, 0x46, 0x2E, 0xCB,
    0xBF, 0x2B, 0x6C, 0x87, 0x9E, 0x64, 0x15, 0x75,
    0x47, 0x96, 0x0D, 0x4A, 0xCE, 0x90, 0xBA, 0x54,
    0x8A, 0x8F, 0x14, 0x10, 0xCC, 0x0B, 0x10, 0x31
  };

  std::vector<char> buf(length_fhdr(name, desc, ts));
  CHECK(buf.size() == sizeof(exp));
  CHECK(write_fhdr(version, name, desc, ts, buf.data()) == buf.size());
  CHECK(!std::memcmp(buf.data(), exp, buf.size()));
}

TEST_CASE("length_hhnn") {
  const HashInfo hi{SFHASH_SHA_1, "SHA-1", 20 };
  CHECK(length_hhnn(hi) == 67);
}

TEST_CASE("write_hhnn") {
/*
  const HashInfo hi{ };

  std::vector<char> buf(length_hhnn(hi));
  CHECK(buf.size() == sizeof(exp));
  CHECK(write_hhnn(hi, 27, buf.data()) == buf.size());
  CHECK(!std::memcmp(buf.data(), exp, buf.size()));
*/

}
