#include "convex_hull.h"

bool operator==(const Point& a, const Point& b) {
  return a.x == b.x && a.y == b.y;
}

bool operator!=(const Point& a, const Point& b) {
  return a.x != b.x || a.y != b.y;
}

// check for right turn with cross product
bool right_turn(const Point& a, const Point& b, const Point& c) {
  // Are the vectors ab and bc a right turn?

//  return (c.x - a.x)*(b.y - a.y) - (c.y - a.y)*(b.x - a.x) > 0;
  return (static_cast<double>(c.x) - static_cast<double>(a.x))*(static_cast<double>(b.y) - static_cast<double>(a.y)) - (static_cast<double>(c.y) - static_cast<double>(a.y))*(static_cast<double>(b.x) - static_cast<double>(a.x)) > 0.0;
}

// This is a Graham scan, which is O(n log n); we could do better with Chan's
// Algorithm, which is O(n log h), where h is the size of the hull
template <
  class Itr
>
auto half_hull(Itr point, Itr end) {
  std::vector<Point> hull;

  hull.push_back(*point++);
  hull.push_back(*point++);
  
  for ( ; point != end; ++point) {
    while (hull.size() > 1 && !right_turn(hull[hull.size()-2], hull[hull.size()-1], *point)) {
      hull.pop_back();
    }
    hull.push_back(*point);
  }

  return hull;
}

// Precondition: points is sorted by x
auto upper_ch(const std::vector<Point>& points) {
  return half_hull(points.begin(), points.end());
}

// Precondition: points is sorted by x
auto lower_ch(const std::vector<Point>& points) {
  return half_hull(points.rbegin(), points.rend());
}
