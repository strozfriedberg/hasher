#include "config.h"

#ifdef HAVE_AVX2_INSTRUCTIONS

#include <x86intrin.h>

#include "hex.h"

__attribute__((target("avx2")))
void to_hex_avx2(char* dst, const uint8_t* src, size_t len) {
  static const __m256i HEX_LUTR_256 = _mm256_setr_epi8(
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  );

  const __m128i* input128 = reinterpret_cast<const __m128i*>(src);
  __m256i* output256 = reinterpret_cast<__m256i*>(dst);

  const size_t tailLen = len & 0x0F;
  const size_t vectLen = len >> 4;
  for (size_t i = 0; i < vectLen; ++i) {
    __m128i av = _mm_loadu_si128(&input128[i]);

    // stretch each byte to one nibble per byte
    __m256i doubled = _mm256_cvtepu8_epi16(av);
    __m256i hi = _mm256_srli_epi16(doubled, 4);
    __m256i lo = _mm256_slli_epi16(doubled, 8);
    __m256i nibs = _mm256_or_si256(hi, lo);
    nibs = _mm256_and_si256(nibs, _mm256_set1_epi8(0b1111));

    // replace each nibble with its ASCII character
    __m256i hexed = _mm256_shuffle_epi8(HEX_LUTR_256, nibs);

    _mm256_storeu_si256(&output256[i], hexed);
  }

  // convert the tail
  to_hex_sse41(dst + (vectLen << 5), src + (vectLen << 4), tailLen);
}

#endif
