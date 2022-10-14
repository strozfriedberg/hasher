#include "rwutil.h"
#include "util.h"

void write_le_8(uint64_t in, const uint8_t* beg, uint8_t*& out, const uint8_t* end) {
  THROW_IF(out + 8 > end, "out of space writing 8 bytes at " << (out - beg));
  *reinterpret_cast<uint64_t*>(out) = to_le(in);
  out += 8;
}
