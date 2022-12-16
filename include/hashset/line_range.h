#pragma

#include <iosfwd>

#include "hashset/line_iterator.h"

class LineRange {
public:
  LineRange(std::istream& in): in(in) {}

  auto begin() const {
    return LineIterator(&in);
  }

  auto end() const {
    return LineIterator();
  }

private:
  std::istream& in;
};
