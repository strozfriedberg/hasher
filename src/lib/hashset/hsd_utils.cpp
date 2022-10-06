#include "hsd_impls/hsd_utils.h"

#include <boost/endian/conversion.hpp>

uint32_t expected_index(const uint8_t* h, uint32_t set_size) {
  /*
   * The expected index for a hash (assuming a uniform distribution) in
   * the hash set is hash/2^(hash length) * set_size. We assume that
   * set_size fits in 32 bits, so nothing beyond the most significant 32
   * bits of the hash can make a difference for the expected index. Hence,
   * we can simplify the expected index to high/2^32 * set_size =
   * (high * set_size)/2^32. Observing that (2^32-1)^2 < (2^32)^2 = 2^64,
   * we see that (high * set_size) fits into 64 bits without overflow, so
   * can compute the expected index as (high * set_size) >> 32.
   */
  const uint64_t high32 = boost::endian::native_to_big<uint32_t>(
    *reinterpret_cast<const uint32_t*>(h)
  );
  return static_cast<uint32_t>((high32 * set_size) >> 32);
}
