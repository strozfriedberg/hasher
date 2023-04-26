#pragma once

#include "config.h"

#include <array>
#include <cstdint>
#include <string>
#include <type_traits>

#if defined(HAVE_FUNC_ATTRIBUTE_IFUNC) && defined(HAVE_FUNC_ATTRIBUTE_TARGET)
__attribute__((target("default")))
void to_hex(char* dst, const void* src, size_t slen);

#ifdef HAVE_X86INTRIN_H
__attribute__((target("sse4.1")))
void to_hex(char* dst, const void* src, size_t slen);

__attribute__((target("avx2")))
void to_hex(char* dst, const void* src, size_t slen);
#endif

#else
void to_hex(char* dst, const void* src, size_t slen);
#endif

template <typename C>
#if defined(HAVE_FUNC_ATTRIBUTE_IFUNC) && defined(HAVE_FUNC_ATTRIBUTE_TARGET_CLONES)
__attribute__((target_clones("avx2", "sse4.1", "default")))
#endif
std::string to_hex(C beg, C end) {
  std::string ret((end - beg) * 2, '\0');
  to_hex(&ret[0], beg, end - beg);
  return ret;
}

template <typename C>
std::string to_hex(const C& c) {
  return to_hex(&c[0], &c[c.size()]);
}

void to_hex_table(char* dst, const uint8_t* src, size_t slen);

#ifdef HAVE_X86INTRIN_H
void to_hex_sse41(char* dst, const uint8_t* src, size_t len);

void to_hex_avx2(char* dst, const uint8_t* src, size_t len);
#endif

void from_hex(uint8_t* dst, const char* src, size_t dlen);

template <size_t N, class = typename std::enable_if<N % 2 == 0>::type>
std::array<uint8_t, N> to_bytes(const char* c) {
  std::array<uint8_t, N> buf;
  from_hex(&buf[0], c, N);
  return buf;
}
