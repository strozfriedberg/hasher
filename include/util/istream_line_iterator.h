#pragma once

#include <iterator>
#include <iosfwd>
#include <string>

class IstreamLineIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = std::string;
  using reference = value_type;
  using pointer = const value_type*;
  using difference_type = std::ptrdiff_t;

  IstreamLineIterator(std::istream* in): in(in), line() {
    advance();
  }

  IstreamLineIterator(): in(nullptr), line() {}

  reference operator*() const {
    return line;
  }

  pointer operator->() const {
    return &line;
  }

  IstreamLineIterator& operator++() {
    advance();
    return *this;
  }

  IstreamLineIterator operator++(int) {
    IstreamLineIterator itr{*this};
    ++(*this);
    return itr;
  }

  bool operator==(const IstreamLineIterator&) const = default;

  bool operator!=(const IstreamLineIterator&) const = default;

private:
  void advance() {
    if (in) {
      if (*in) {
        std::getline(*in, line);
      }
      else {
        in = nullptr;
      }
    }
  }

  std::istream* in;
  std::string line;
};

static_assert(std::input_iterator<IstreamLineIterator>);
