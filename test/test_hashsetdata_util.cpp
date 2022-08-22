#include <catch2/catch_test_macros.hpp>

#include "hex.h"
#include "hsd_impls/hsd_utils.h"

#include <array>
#include <tuple>
#include <utility>
#include <vector>

TEST_CASE("expected_indexTest") {
  const std::vector<std::tuple<std::array<uint8_t,20>, uint32_t, uint32_t>> tests{
    {to_bytes<20>("0000000000000000000000000000000000000000"), 1000,   0},
    {to_bytes<20>("7fffffffffffffffffffffffffffffffffffffff"), 1000, 499},
    {to_bytes<20>("8000000000000000000000000000000000000000"), 1000, 500},
    {to_bytes<20>("ffffffffffffffffffffffffffffffffffffffff"), 1000, 999}
  };

  for (const auto& t: tests) {
    REQUIRE(std::get<2>(t) ==
                       expected_index(std::get<0>(t).data(), std::get<1>(t)));
  }
}

/*
TEST_CASE("compute_radiusTest") {
  std::vector<std::array<uint8_t, 20>> hashes;
  for (const auto& p: test1_in) {
    hashes.push_back(p.first);
  }

  REQUIRE(
    test1_info.radius ==
    compute_radius(hashes.data(), hashes.data() + hashes.size())
  );
}
*/
