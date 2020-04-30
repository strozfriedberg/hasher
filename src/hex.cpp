#include "hex.h"
#include "throw.h"

#include "hasher/api.h"

void to_hex(char* dst, const void* src, size_t slen) {
  to_hex(dst, static_cast<const uint8_t*>(src),
              static_cast<const uint8_t*>(src) + slen);
}

uint8_t char_to_nibble(char c) {
  //  return 9*(c >> 6) + (c & 0x0F);
  if ('0' <= c && c <= '9') {
    return c - '0';
  }
  else if ('A' <= c && c <= 'F') {
    return c - 'A' + 10;
  }
  else if ('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  }
  else {
    THROW("'" << c << "' is not a hexadecimal digit");
  }
}

void from_hex(uint8_t* dst, const char* src, size_t dlen) {
  const char* const end = src + 2*dlen;
  for (; src != end; ++dst, src += 2) {
    *dst = (char_to_nibble(*src) << 4) | char_to_nibble(*(src + 1));
  }
}

void sfhash_hex(char* dst, const void* src, size_t slen) {
  to_hex(dst, static_cast<const uint8_t*>(src),
              static_cast<const uint8_t*>(src) + slen);
}

bool sfhash_unhex(uint8_t* dst, const char* src, size_t dlen) {
  try {
    from_hex(dst, src, dlen);
    return true;
  }
  catch (const std::exception& e) {
    return false;
  }
}
