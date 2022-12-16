#pragma once

#include <iterator>
#include <iosfwd>
#include <string>

#include "hashset/arrow_proxy.h"

class LineIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = std::string_view;
  using reference = value_type;
  using pointer = ArrowProxy<reference>;
  using difference_type = std::ptrdiff_t;

  LineIterator(std::istream* in): in(in), line() {
    advance();
  }

  LineIterator(): in(nullptr), line() {}

/*
  LineIterator(LineIterator&) = default;

  LineIterator(LineIterator&&) = default;

  LineIterator& operator=(const LineIterator&) = default;

  LineIterator& operator=(LineIterator&&) = default;
*/

  reference operator*() const {
    return line;
  }

  pointer operator->() const {
    return pointer{{line}};
  }

  LineIterator& operator++() {
    advance();
    return *this;
  }

  LineIterator operator++(int) {
    LineIterator itr{*this};
    ++(*this);
    return itr;
  }

  bool operator==(const LineIterator&) const = default;

  bool operator!=(const LineIterator&) const = default;

private:
  void advance() {
    if (in) {
      if (*in) {
        std::getline(*in, line);
      }
      else {
        in = nullptr;
        line = "";
      }
    }
  }

  std::istream* in;
  std::string line;
};

static_assert(std::input_iterator<LineIterator>);
