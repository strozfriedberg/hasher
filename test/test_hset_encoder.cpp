#include "hset_encoder.h"

#include <initializer_list>
#include <string>
#include <utility>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("size_to_u64") {
  uint8_t dst[8];

  const std::initializer_list<std::pair<const char*, uint64_t>> good = {
    { "0", 0 },
    { "42", 42 },
    { "10000000", 10000000 },
    { "18446744073709551615", 0xFFFFFFFFFFFFFFFF }
  };

  for (const auto& [in, exp]: good) {
    DYNAMIC_SECTION(in << ' ' << exp) {
      size_to_u64(dst, in, 8);
      CHECK(*reinterpret_cast<const uint64_t*>(dst) == exp);
    }
  }

  const auto bad = {
    "-1",                   // too small
    "18446744073709551616", // too large
    "3.7",                  // not an integer
    "Bob"                   // not a number
  };

  for (const auto& in: bad) {
    DYNAMIC_SECTION(in << " throws") {
      CHECK_THROWS(size_to_u64(dst, in, 8));
    }
  }
}
