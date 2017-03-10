#pragma once

#include <ostream>
#include <utility>

template <typename F, typename S>
std::ostream& operator<<(std::ostream& o, const std::pair<F,S>& p) {
  return o << '(' << p.first << ", " << p.second << ')';
}
