#include "util.h"

#include <boost/endian/conversion.hpp>

uint64_t read_le_8(const uint8_t* beg, const uint8_t*& i, const uint8_t* end) {
  THROW_IF(i + 8 > end, "out of data reading 8 bytes at " << (i-beg));
  const uint64_t r = boost::endian::little_to_native(*reinterpret_cast<const uint64_t*>(i));
  i += 8;
  return r;
}

void write_le_8(uint64_t in, const uint8_t* beg, uint8_t*& out, const uint8_t* end) {
  THROW_IF(out + 8 > end, "out of space writing 8 bytes at " << (out - beg));
  *reinterpret_cast<uint64_t*>(out) = boost::endian::native_to_little(in);
  out += 8;
}
