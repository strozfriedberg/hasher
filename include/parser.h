#pragma once

#include "util.h"

#include <iterator>
#include <tuple>
#include <utility>

enum {
  // anonymous enum
  BLANK_LINE        = 0,
  HAS_FILENAME      = 1,
  HAS_SIZE_AND_HASH = 2
};

struct ParsedLine {
  std::string name;
  sha1_t hash;
  uint64_t size;
  uint8_t flags;
};

ParsedLine parse_line(const char* beg, const char* const end);

class LineIterator {
public:
  using difference_type   = std::ptrdiff_t;
  using value_type        = std::pair<const char*, const char*>;
  using pointer           = value_type*;
  using reference         = value_type&;
  using iterator_category = std::input_iterator_tag;

  LineIterator(const char* beg, const char* end):
    Pos(beg, find_next(beg, end)),
    End(end)
  {}

  LineIterator(const LineIterator&) = default;

  LineIterator& operator=(const LineIterator&) = default;

  const value_type& operator*() const;

  const value_type* operator->() const;

  LineIterator& operator++();

  LineIterator operator++(int);

  bool operator==(const LineIterator& o) const;

  bool operator!=(const LineIterator& o) const;

private:
  static const char* find_next(const char* cur, const char* end);

  value_type Pos;
  const char* const End;
};
