#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "hashset/convex_hull.h"

TEST_CASE("Point_equality") {
  CHECK(Point<int>{0,0} == Point<int>{0,0});
}

TEST_CASE("Point_inequality") {
  CHECK(Point<int>{0,0} != Point<int>{0,1});
  CHECK(Point<int>{0,0} != Point<int>{1,0});
  CHECK(Point<int>{0,0} != Point<int>{1,1});
}

TEST_CASE("convex_hull_square") {
  // the vertices of square, plus the center point
  const std::vector<Point<int>> points{
    {0,0}, {0,10}, {5,5}, {10,0}, {10,10}
  };

  const std::vector<Point<int>> exp_lower{{10,10}, {10,0}, {0,0}};
  CHECK(lower_ch(points) == exp_lower);

  const std::vector<Point<int>> exp_upper{{0,0}, {0,10}, {10,10}};
  CHECK(upper_ch(points) == exp_upper);
}
