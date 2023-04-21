#include "hashset/hset_decoder.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("printable_chunk_type_ABCD") {
  CHECK(printable_chunk_type(0x41424344) == "ABCD");
}

TEST_CASE("printable_chunk_type_HH02") {
  CHECK(printable_chunk_type(0x48480002) == "HH 0002");
}
