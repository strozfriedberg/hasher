#include <catch2/catch_test_macros.hpp>

#include "convex_hull.h"

TEST_CASE("Point_equality") {
  CHECK(Point{0,0} == Point{0,0});
}

TEST_CASE("Point_inequality") {
  CHECK(Point{0,0} != Point{0,1});
  CHECK(Point{0,0} != Point{1,0});
  CHECK(Point{0,0} != Point{1,1});
}
