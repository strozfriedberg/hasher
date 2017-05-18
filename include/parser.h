#pragma once

#include "util.h"

#include <iterator>
#include <tuple>
#include <utility>

enum {
  BLANK_LINE = 0,
  HAS_FILENAME = 1,
  HAS_SIZE_AND_HASH = 2
};

std::tuple<uint8_t, std::string, uint64_t, sha1_t> parse_line(const char* beg, const char* const end);

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
