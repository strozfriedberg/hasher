#include "rwutil.h"

#include <ostream>
#include <vector>

template <>
size_t write_to(std::ostream& out, const void* buf, size_t len) {
  out.write(static_cast<const char*>(buf), len);
  return len;
}

template <>
size_t write_to(std::vector<char>& out, const void* buf, size_t len) {
  out.insert(
    out.end(),
    static_cast<const char*>(buf),
    static_cast<const char*>(buf) + len
  );
  return len;
}
