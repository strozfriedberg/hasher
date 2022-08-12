#pragma once

#include <iosfwd>
#include <vector>

struct Point {
  int x;
  int y;
};

bool operator==(const Point& a, const Point& b);

bool operator!=(const Point& a, const Point& b);

std::ostream& operator<<(std::ostream& out, const Point& p);

// Precondition: points is sorted by x
std::vector<Point> upper_ch(const std::vector<Point>& points);

// Precondition: points is sorted by x
std::vector<Point> lower_ch(const std::vector<Point>& points);
