#include "config.h"

#ifdef HAVE_SSE4_1_INSTRUCTIONS

#include <x86intrin.h>

#include "hex.h"

__attribute__((target("sse4.1")))
void to_hex_sse41(char* dst, const uint8_t* src, size_t len) {
  static const __m128i HEX_LUTR = _mm_setr_epi8(
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  );

  const __m64* input64 = reinterpret_cast<const __m64*>(src);
  __m128i* output128 = reinterpret_cast<__m128i*>(dst);

  const size_t tailLen = len & 0x07;
  const size_t vectLen = len >> 3;
  for (size_t i = 0; i < vectLen; ++i) {
    __m128i av = _mm_loadu_si64(&input64[i]);

    // stretch each byte to one nibble per byte
    __m128i doubled = _mm_cvtepu8_epi16(av);
    __m128i hi = _mm_srli_epi16(doubled, 4);
    __m128i lo = _mm_slli_epi16(doubled, 8);
    __m128i nibs = _mm_or_si128(hi, lo);
    nibs = _mm_and_si128(nibs, _mm_set1_epi8(0b1111));

    // replace each nibble with its ASCII character
    __m128i hexed = _mm_shuffle_epi8(HEX_LUTR, nibs);

    _mm_storeu_si128(&output128[i], hexed);
  }

  // convert the tail
  to_hex_table(dst + (vectLen << 4), src + (vectLen << 3), tailLen);
}

#endif
