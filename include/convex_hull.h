#pragma once

#include <vector>

struct Point {
  int x;
  int y;
};

bool operator==(const Point& a, const Point& b);

bool operator!=(const Point& a, const Point& b);

// Precondition: points is sorted by x
auto upper_ch(const std::vector<Point>& points); 

// Precondition: points is sorted by x
auto lower_ch(const std::vector<Point>& points);
