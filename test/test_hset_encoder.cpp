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
  const HashInfo hi{SFHASH_SHA_1, "SHA-1", 20, nullptr};
  CHECK(length_hhnn(hi) == 67);
}

TEST_CASE("write_hhnn") {
  const HashInfo hi{SFHASH_SHA_1, "SHA-1", 20 , nullptr};

  const uint8_t exp[] = {
    // chunk type
    'H', 'H', 0x00, 0x01,
    // chunk data length
    0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash type name length
    0x05, 0x00,
    // hash type name
    'S', 'H', 'A', '-', '1',
    // hash length
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash count
    0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00,
    // chunk hash
    0x6F, 0xA9, 0xE5, 0xDC, 0xAF, 0x7B, 0x01, 0xCD,
    0x36, 0xB7, 0x83, 0x5F, 0x32, 0xE1, 0xF8, 0x92,
    0x04, 0x27, 0x0F, 0xAD, 0xF2, 0xF2, 0xB6, 0x7D,
    0x13, 0x3F, 0x9E, 0x37, 0xA5, 0xCA, 0x65, 0x7D
  };

  std::vector<char> buf(length_hhnn(hi));
  CHECK(buf.size() == sizeof(exp));
  CHECK(write_hhnn(hi, 4886718345, buf.data()) == buf.size());
  CHECK(!std::memcmp(buf.data(), exp, buf.size()));
}

TEST_CASE("length_hint") {
//  CHECK(length_hhnn(hi) == 4142);
}

TEST_CASE("write_hint") {
/*
  const HashInfo hi{SFHASH_SHA_1, "SHA-1", 20 };

  const uint8_t exp[] = {
    // chunk type
    'H', 'H', 0x00, 0x01,
    // chunk data length
    0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash type name length
    0x05, 0x00,
    // hash type name
    'S', 'H', 'A', '-', '1',
    // hash length
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash count
    0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00,
    // chunk hash
    0x7A, 0xCC, 0x42, 0x6D, 0x65, 0x73, 0x5B, 0x47,
    0x8F, 0x85, 0x84, 0xC0, 0xAD, 0x66, 0xDA, 0x38,
    0x2B, 0xEB, 0x27, 0xDF, 0x32, 0x32, 0x08, 0x27,
    0x4C, 0x03, 0xDF, 0x51, 0xF9, 0x5E, 0x55, 0xD0
  };

  std::vector<char> buf(length_hhnn(hi));
  CHECK(buf.size() == sizeof(exp));
  CHECK(write_hinthnn(hi, 4886718345, buf.data()) == buf.size());
  CHECK(!std::memcmp(buf.data(), exp, buf.size()));
*/
}

TEST_CASE("length_hdat") {
  CHECK(length_hdat(3914, 20) == 78324);
}

TEST_CASE("write_hdat") {
  const std::vector<std::vector<uint8_t>> hashes{
    {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      0x00, 0x11, 0x22, 0x33
    },
    {
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01
    }
  };

  const uint8_t exp[] = {
    // chunk type
    'H', 'D', 'A', 'T',
    // chunk data length
    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash 0
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x11, 0x22, 0x33,
    // hash 1
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01,
    // chunk hash
    0xBC, 0xBB, 0x2A, 0x5B, 0x55, 0x86, 0x1C, 0x40,
    0xA6, 0x47, 0x71, 0x0D, 0x1D, 0xE6, 0xA0, 0x30,
    0xA9, 0xE8, 0x95, 0x54, 0x46, 0xEE, 0xC9, 0x29,
    0x3C, 0x11, 0x1E, 0x54, 0x8E, 0x93, 0xAC, 0x0D
  };

  std::vector<char> buf(length_hdat(hashes.size(), 20));
  CHECK(buf.size() == sizeof(exp));
  CHECK(write_hdat(hashes, buf.data()) == buf.size());
  CHECK(!std::memcmp(buf.data(), exp, buf.size()));
}

TEST_CASE("length_ridx") {
  CHECK(length_ridx(134) == 1116);
}

TEST_CASE("write_ridx") {
  const std::vector<uint64_t> ridx{
    0,
    97,
    12345678
  };

  const uint8_t exp[] = {
    // chunk type
    'R', 'I', 'D', 'X',
    // chunk data length
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // index 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // index 1
    0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // index 2
    0x4E, 0x61, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00,
    // chunk hash
    0x4F, 0xE4, 0xC9, 0x93, 0x6F, 0x17, 0x19, 0xB6,
    0x0B, 0xB1, 0x40, 0x55, 0x3F, 0xEC, 0x12, 0x9A,
    0xF4, 0x7D, 0x12, 0xC7, 0x35, 0xB3, 0x6E, 0x2B,
    0x8A, 0x47, 0x28, 0x0B, 0x59, 0x6C, 0xF4, 0x9B
  };

  std::vector<char> buf(length_ridx(ridx.size()));
  CHECK(buf.size() == sizeof(exp));
  CHECK(write_ridx(ridx, buf.data()) == buf.size());
  CHECK(!std::memcmp(buf.data(), exp, buf.size()));
}

/*
  for (char c: buf) {
    std::cerr << std::hex << std::setw(2) << std::setfill('0') << (c & 0xFF) << ' ';
  }
  std::cerr << '\n';
*/
