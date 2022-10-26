#include "hset_encoder.h"
#include "hex.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
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

TEST_CASE("write_page_alignment_padding_at_0") {
  std::vector<char> out;
  Writer w{write_vec, &out};

  CHECK(write_page_alignment_padding(0, 4096, w) == 0);
  CHECK(out.size() == 0);
}

TEST_CASE("write_page_alignment_padding_aligned") {
  std::vector<char> out;
  Writer w{write_vec, &out};

  CHECK(write_page_alignment_padding(8192, 4096, w) == 0);
  CHECK(out.size() == 0);
}

TEST_CASE("write_page_alignment_padding_not_aligned") {
  std::vector<char> out;
  Writer w{write_vec, &out};

  CHECK(write_page_alignment_padding(75, 4096, w) == 4096 - 75);
  CHECK(out.size() == 4096 - 75);
  CHECK(std::all_of(out.begin(), out.end(), [](char c){ return c == '\0'; }));
}


