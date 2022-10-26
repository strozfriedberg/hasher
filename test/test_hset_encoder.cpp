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

ssize_t write_vec(void* ctx, const void* buf, size_t len) {
  static_cast<std::vector<char>*>(ctx)->insert(
    static_cast<std::vector<char>*>(ctx)->end(),
    static_cast<const char*>(buf),
    static_cast<const char*>(buf) + len
  );
  return static_cast<ssize_t>(len);
}

TEST_CASE("write_chunk_nonempty") {
  const char type[] = "ABCD";
  const char data[] = "0123456789";

  REQUIRE(std::strlen(data) == 10);

  // echo -n 0123456789 | sha256sum
  const auto hash = to_bytes<32>("84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882");

  REQUIRE(hash.size() == 32);

  std::vector<char> out;
  Writer w{write_vec, &out};

  const uint64_t exp_size = 4 + 8 + 10 + 32;

  // Output size
  CHECK(write_chunk(type, data, 10, w) == exp_size);
  CHECK(out.size() == exp_size);

  // Output value
  auto c = out.cbegin();
  CHECK(std::equal(c, c + 4, type));
  c += 4;

  const auto dlen = { 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  CHECK(std::equal(c, c + 8, dlen.begin()));
  c += 8;

  CHECK(std::equal(c, c + 10, data));
  c += 10;

  CHECK(std::equal(c, c + hash.size(), reinterpret_cast<const char*>(hash.data())));
}
*/

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
    'F', 'H', 'D', 'R',
    0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00,
    'n', 'a', 'm', 'e',
    0x14, 0x00,
    '2', '0', '2', '2', '-', '1', '0', '-', '2', '6', 'T', '1', '8', ':', '1', '3', ':', '0', '7', 'Z',
    0x04, 0x00,
    'd', 'e', 's', 'c',
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
