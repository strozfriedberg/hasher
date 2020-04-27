#pragma once

#include <array>
#include <string>
#include <type_traits>

template <typename C>
void to_hex(char* dst, C beg, C end) {
  static constexpr char hex[] {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };

  for (C c = beg; c != end; ++c) {
    const uint8_t lo = *c & 0x0F;
    const uint8_t hi = *c >> 4;

    *dst++ = hex[hi];
    *dst++ = hex[lo];
  }
}

template <typename C>
std::string to_hex(C beg, C end) {
  std::string ret((end - beg) * 2, '\0');
  to_hex(&ret[0], beg, end);
  return ret;
}

template <typename C>
std::string to_hex(const C& c) {
  return to_hex(&c[0], &c[c.size()]);
}

void from_hex(uint8_t* dst, const char* src, size_t dlen);

template <size_t N, class = typename std::enable_if<N % 2 == 0>::type>
std::array<uint8_t, N> to_bytes(const char* c) {
  std::array<uint8_t, N> buf;
  from_hex(&buf[0], c, N);
  return buf;
}
