#pragma once

#include <cmath>

/*
 * Stand-ins we can use C++20
 */

template <class T>
constexpr int bit_width(T x) noexcept {
  return std::floor(std::log2(x)) + 1;
}

template <class T>
class span {
public:
  constexpr span() noexcept: beg(nullptr), end(nullptr) {}

  template <class It>
  constexpr span(It first, size_t count): beg(first), end(first + count) {}

  template <std::size_t N>
  constexpr span(T (&arr)[N]) noexcept: beg(arr), end(arr + N) {}

  constexpr span(const span<std::remove_const_t<T>>& o) noexcept:
    beg(o.data()), end(o.data() + o.size()) {}

  constexpr span& operator=(const span<std::remove_const_t<T>>& o) noexcept {
    beg = o.data();
    end = o.data() + o.size();
    return *this;
  }

  constexpr T& operator[](size_t idx) const {
    return beg[idx];
  }

  constexpr T* data() const noexcept {
    return beg;
  }

  constexpr size_t size() const noexcept {
    return end - beg;
  }

private:
  T* beg;
  T* end; 
};
