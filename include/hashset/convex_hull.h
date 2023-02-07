#pragma once

#include <ostream>
#include <vector>

template <class T>
struct Point {
  // C++20: remove unnecessary ctor
  Point(T x, T y): x(x), y(y) {}

  T x;
  T y;
};

template <class T>
bool operator==(const Point<T>& a, const Point<T>& b) {
  return a.x == b.x && a.y == b.y;
}

template <class T>
bool operator!=(const Point<T>& a, const Point<T>& b) {
  return a.x != b.x || a.y != b.y;
}

template <class T>
std::ostream& operator<<(std::ostream& out, const Point<T>& p) {
  return out << '(' << p.x << ',' << p.y << ')';
}

// Precondition: points is sorted by x
template <class T>
std::vector<Point<T>> upper_ch(const std::vector<Point<T>>& points) {
  return half_hull(points.begin(), points.end());
}

// Precondition: points is sorted by x
template <class T>
std::vector<Point<T>> lower_ch(const std::vector<Point<T>>& points) {
 return half_hull(points.rbegin(), points.rend());
}

// check for right turn with cross product
template <class T>
bool right_turn(const Point<T>& a, const Point<T>& b, const Point<T>& c) {
  // Are the vectors ab and bc a right turn?

//  return (c.x - a.x)*(b.y - a.y) - (c.y - a.y)*(b.x - a.x) > 0;
  return (static_cast<double>(c.x) - static_cast<double>(a.x))*(static_cast<double>(b.y) - static_cast<double>(a.y)) - (static_cast<double>(c.y) - static_cast<double>(a.y))*(static_cast<double>(b.x) - static_cast<double>(a.x)) > 0.0;
}

// This is a Graham scan, which is O(n log n); we could do better with Chan's
// Algorithm, which is O(n log h), where h is the size of the hull
template <class Itr>
auto half_hull(Itr point, Itr end) {
  std::vector<typename Itr::value_type> hull;

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
