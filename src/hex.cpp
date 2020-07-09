#include "hex.h"
#include "throw.h"

#include "hasher/api.h"

__attribute__((target("default")))
void to_hex(char* dst, const void* src, size_t slen) {
  to_hex_table(dst, static_cast<const uint8_t*>(src), slen);
}

__attribute__((target("sse4.1")))
void to_hex(char* dst, const void* src, size_t slen) {
  to_hex_sse41(dst, static_cast<const uint8_t*>(src), slen);
}

__attribute__((target("avx2")))
void to_hex(char* dst, const void* src, size_t slen) {
  to_hex_avx2(dst, static_cast<const uint8_t*>(src), slen);
}

void to_hex_table(char* dst, const uint8_t* src, size_t slen) {
  static constexpr char hex[] {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };

  const uint8_t* const end = src + slen;
  for (const uint8_t* c = src; c != end; ++c) {
    const uint8_t lo = *c & 0x0F;
    const uint8_t hi = *c >> 4;

    *dst++ = hex[hi];
    *dst++ = hex[lo];
  }
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

void sfhash_hex(char* dst, const void* src, size_t len) {
  to_hex(dst, src, len);
}

bool sfhash_unhex(uint8_t* dst, const char* src, size_t len) {
  if (len & 1) {
    // length of hex strings must be even
    return false;
  }

  try {
    from_hex(dst, src, len >> 1);
    return true;
  }
  catch (const std::exception& e) {
    return false;
  }
}
