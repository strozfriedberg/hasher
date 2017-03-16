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
    cur(beg), next(find_next(beg, end)), end(end) {}

  LineIterator(const LineIterator&) = default;

  LineIterator& operator=(const LineIterator&) = default;

  value_type operator*() const { return {cur, next}; }

  LineIterator& operator++() {
    if (next == end) {
      cur = end;
    }
    else {
      cur = next + (*next == '\r' ? 2 : 1);
      next = find_next(cur, end);
    }
    return *this;
  }

  LineIterator operator++(int) {
    LineIterator i(*this);
    ++*this;
    return i;
  }

  bool operator==(const LineIterator& o) const {
    return cur == o.cur && next == o.next;
  }

  bool operator!=(const LineIterator& o) const {
    return !(*this == o);
  }

private:
  static const char* find_next(const char* pos, const char* end) {
    const char* i = std::find(pos, end, '\n');
    return (i == end || *(i-1) != '\r') ? i : i-1;
  }

  const char* cur;
  const char* next;
  const char* const end;
};

class HashsetIterator {
public:
  using difference_type = std::ptrdiff_t;
  using value_type = std::tuple<std::string, size_t, sha1_t>;
  using pointer = value_type*;
  using reference = value_type&; 
  using iterator_category = std::input_iterator_tag;

  HashsetIterator(const char* beg, const char* end):
    li(beg, end), lend(end, end), done(li == lend)
  {
    if (!done) {
      t = fill(li); 
    }
  }

  HashsetIterator():
    li(nullptr, nullptr), lend(nullptr, nullptr), done(true) {}

  HashsetIterator(const HashsetIterator&) = default;

  HashsetIterator& operator=(const HashsetIterator&) = default;

  const value_type& operator*() const { return t; }

  HashsetIterator& operator++() {
    if (li != lend) {
      t = fill(li);
    }
    else if (!done) {
      done = true;
    }
    return *this;
  }

  HashsetIterator operator++(int) {
    HashsetIterator ret(*this);
    ++*this;
    return ret;
  }

  bool operator==(const HashsetIterator& o) const {
    return done ? o.done : li == o.li;
  }

  bool operator!=(const HashsetIterator& o) const { return !(*this == o); }

private:
  static value_type fill(LineIterator& li) {
    const char* i;
    const char* j;
    const char* end;
    std::tie(i, end) = *li;
    ++li;

    THROW_IF(i == end, "premature end of tokens");
    j = std::find(i, end, '\t');
    THROW_IF(j == end, "premature end of tokens");
    std::string name(i, j);

    i = j + 1;
    THROW_IF(i == end, "premature end of tokens");
    j = std::find(i, end, '\t');
    THROW_IF(j == end, "premature end of tokens");
    const size_t size = boost::lexical_cast<size_t>(i, j - i);

    i = j + 1;
    THROW_IF(i == end, "premature end of tokens");
    j = i + 40;
    THROW_IF(j != end, "too many tokens");
    sha1_t hash = to_bytes<20>(i);

    return {std::move(name), size, std::move(hash)};
  }

  LineIterator li, lend;
  value_type t;
  bool done;
};
