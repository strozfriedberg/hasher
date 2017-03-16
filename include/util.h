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

template <size_t N, typename C>
std::array<uint8_t, N> to_bytes(C beg, C end) {
  // TODO: fail if end - beg is odd
  // TODO: fail if end - beg != N

  std::array<uint8_t, N> buf;
  uint8_t* out = &buf[0];
  for (C c = beg; c != end; ++out, c += 2) {
    *out = (char_to_nibble(*c) << 4) | char_to_nibble(*(c+1));
  }

  return std::move(buf);
}

template <size_t N>
std::array<uint8_t, N> to_bytes(const char* s) {
  return to_bytes<N>(s, s + std::strlen(s));
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

class TokenIterator {
public:
  using difference_type = std::ptrdiff_t;
  using value_type = std::pair<const char*, const char*>;
  using pointer = value_type*;
  using reference = value_type&; 
  using iterator_category = std::input_iterator_tag;

  TokenIterator(const char* beg, const char* end):
    cur(beg), next(find_next(beg, end, 1)), end(end), count(1) {}

  TokenIterator(const TokenIterator&) = default;

  TokenIterator& operator=(const TokenIterator&) = default;

  value_type operator*() const { return {cur, next}; }

  TokenIterator& operator++() {
    cur = next + 1;
    next = find_next(cur, end, ++count);
    return *this;
  }

  TokenIterator operator++(int) {
    TokenIterator i(*this);
    ++*this;
    return i;
  }

  bool operator==(const TokenIterator& o) const {
    return cur == o.cur && next == o.next;
  }

  bool operator!=(const TokenIterator& o) const {
    return !(*this == o); 
  }

private:
  static const char* find_next(const char* pos, const char* end, uint32_t count) {
  return std::find(pos, end, count % 3 ? '\t' : '\n');
}

  const char* cur;
  const char* next;
  const char* const end;
  uint32_t count;
};

class HashsetIterator {
public:
  using difference_type = std::ptrdiff_t;
  using value_type = std::tuple<std::string, size_t, sha1_t>;
  using pointer = value_type*;
  using reference = value_type&; 
  using iterator_category = std::input_iterator_tag;

  HashsetIterator(const char* beg, const char* end):
    i(beg, end), iend(end, end), done(i == iend)
  {
    if (!done) {
      t = fill(i, iend); 
    }
  }

  HashsetIterator(): i(nullptr, nullptr), iend(nullptr, nullptr), done(true) {}

  HashsetIterator(const HashsetIterator&) = default;

  HashsetIterator& operator=(const HashsetIterator&) = default;

  const value_type& operator*() const { return t; }

  HashsetIterator& operator++() {
    if (i != iend) {
      t = fill(i, iend);
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
    return done ? o.done : i == o.i;
  }

  bool operator!=(const HashsetIterator& o) const { return !(*this == o); }

private:
  static value_type fill(TokenIterator& i, const TokenIterator iend) {
    const char* tbeg;
    const char* tend;

// TODO: error checking
    std::tie(tbeg, tend) = *i;
    std::string name(tbeg, tend);
    std::tie(tbeg, tend) = *++i;
    size_t size = boost::lexical_cast<size_t>(tbeg, tend - tbeg);
    std::tie(tbeg, tend) = *++i;
    sha1_t hash = to_bytes<20, const char*>(tbeg, tend);
    ++i;
    return {std::move(name), size, std::move(hash)};
  }

  TokenIterator i, iend;
  value_type t;
  bool done;
};
