#include "catch.hpp"

#include <iterator>
#include <stdexcept>

#include "util.h"


TEST_CASE("test_read_le_8") {
  const uint8_t x[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB
  };

  const uint8_t* i = &x[0];
  REQUIRE(0xEFCDAB8967452301 == read_le_8(std::begin(x), i, std::end(x)));
  REQUIRE_THROWS_AS(read_le_8(std::begin(x), i, std::end(x)), std::runtime_error);
}

TEST_CASE("test_write_le_8") {
  uint8_t buf[16];
  uint8_t* out = buf;

  write_le_8(0x0123456789ABCDEF, buf, out, buf + sizeof(buf));
  REQUIRE(buf + 8 == out);
  REQUIRE(0xEF == buf[0]);
  REQUIRE(0xCD == buf[1]);
  REQUIRE(0xAB == buf[2]);
  REQUIRE(0x89 == buf[3]);
  REQUIRE(0x67 == buf[4]);
  REQUIRE(0x45 == buf[5]);
  REQUIRE(0x23 == buf[6]);
  REQUIRE(0x01 == buf[7]);
}
