#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <algorithm>
#include <random>

#include "hex.h"

TEST_CASE("to_hex") {
  // fill a buffer with random data
  uint8_t src[1024];

  std::independent_bits_engine<std::default_random_engine, sizeof(uint8_t), uint8_t> be;
  std::generate(std::begin(src), std::end(src), std::ref(be));

  char dst[2*sizeof(src)];

  // to_hex will use whichever algorithm is selected at runtime
  BENCHMARK("to_hex") {
    to_hex(dst, src, sizeof(src));
    return dst;
  };

  BENCHMARK("to_hex_table") {
    to_hex_table(dst, src, sizeof(src));
    return dst;
  };

  BENCHMARK("to_hex_sse41") {
    to_hex_sse41(dst, src, sizeof(src));
    return dst;
  };

  BENCHMARK("to_hex_avx2") {
    to_hex_avx2(dst, src, sizeof(src));
    return dst;
  };
}
