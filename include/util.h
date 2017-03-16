#pragma once

#include <algorithm>
#include <array>
#include <iomanip>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>

#include <boost/lexical_cast.hpp>

#include "throw.h"

template <class T, class D>
std::unique_ptr<T, D> make_unique_del(T* p, D&& deleter) {
  return std::unique_ptr<T, D>{p, std::forward<D>(deleter)};
}

template <typename C>
std::string to_hex(C beg, C end) {
  std::ostringstream o;
  o << std::setfill('0') << std::hex;
  for (C c = beg; c != end; ++c) {
    o << std::setw(2) << static_cast<uint32_t>(*c);
  }
  return o.str();
}

template <typename C>
std::string to_hex(const C& c) {
  return to_hex(&c[0], &c[c.size()]);
}

template <size_t N>
using hash_t = std::array<uint8_t, N>;

using md5_t = hash_t<16>;
using sha1_t = hash_t<20>;
using sha256_t = hash_t<32>;

uint8_t char_to_nibble(char c);

template <
  size_t N,
  class = typename std::enable_if<N % 2 == 0>::type
>
std::array<uint8_t, N> to_bytes(const char* c) {
  std::array<uint8_t, N> buf;
  uint8_t* out = &buf[0];
  const char* const end = c + 2*N;
  for ( ; c != end; ++out, c += 2) {
    *out = (char_to_nibble(*c) << 4) | char_to_nibble(*(c+1));
  }

  return std::move(buf);
}

class LineIterator {
public:
  using difference_type = std::ptrdiff_t;
  using value_type = std::pair<const char*, const char*>;
  using pointer = value_type*;
  using reference = value_type&;
  using iterator_category = std::input_iterator_tag;

  LineIterator(const char* beg, const char* end):
    pos(beg, find_next(beg, end)), end(end) {}

  LineIterator(const LineIterator&) = default;

  LineIterator& operator=(const LineIterator&) = default;

  const value_type& operator*() const { return pos; }

  const value_type* operator->() const { return &pos; }

  LineIterator& operator++() {
    if (pos.second == end) {
      pos.first = end;
    }
    else {
      pos.first = pos.second + (*pos.second == '\r' ? 2 : 1);
      pos.second = find_next(pos.first, end);
    }
    return *this;
  }

  LineIterator operator++(int) {
    LineIterator i(*this);
    ++*this;
    return i;
  }

  bool operator==(const LineIterator& o) const {
    return pos == o.pos;
  }

  bool operator!=(const LineIterator& o) const {
    return !(*this == o);
  }

private:
  static const char* find_next(const char* cur, const char* end) {
    const char* i = std::find(cur, end, '\n');
    return (i == end || *(i-1) != '\r') ? i : i-1;
  }

  value_type pos;
  const char* const end;
};
