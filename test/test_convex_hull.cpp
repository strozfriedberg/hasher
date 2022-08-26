#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "hsd_impls/convex_hull.h"

TEST_CASE("Point_equality") {
  CHECK(Point{0,0} == Point{0,0});
}

TEST_CASE("Point_inequality") {
  CHECK(Point{0,0} != Point{0,1});
  CHECK(Point{0,0} != Point{1,0});
  CHECK(Point{0,0} != Point{1,1});
}

TEST_CASE("convex_hull_square") {
  // the vertices of square, plus the center point
  const std::vector<Point> points{
    {0,0}, {0,10}, {5,5}, {10,0}, {10,10}
  };

  const std::vector<Point> exp_lower{{10,10}, {10,0}, {0,0}};
  CHECK(lower_ch(points) == exp_lower);

  const std::vector<Point> exp_upper{{0,0}, {0,10}, {10,10}};
  CHECK(upper_ch(points) == exp_upper);
}
