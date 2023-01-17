#pragma once

#include <iosfwd>

#include "util/istream_line_iterator.h"

class IstreamLineRange {
public:
  IstreamLineRange(std::istream& in): in(in) {}

  auto begin() const {
    return IstreamLineIterator(&in);
  }

  auto end() const {
    return IstreamLineIterator();
  }

private:
  std::istream& in;
};
