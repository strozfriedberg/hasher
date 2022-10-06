#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <stdint.h>

#include <hasher/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 Hash types
******************************************************************************/

// Bit flags for specifying hash algorithms
typedef enum {
  SFHASH_MD5       = 1 <<  0,
  SFHASH_SHA_1     = 1 <<  1,
  SFHASH_SHA_2_224 = 1 <<  2,
  SFHASH_SHA_2_256 = 1 <<  3,
  SFHASH_SHA_2_384 = 1 <<  4,
  SFHASH_SHA_2_512 = 1 <<  5,
  SFHASH_SHA_3_224 = 1 <<  6,
  SFHASH_SHA_3_256 = 1 <<  7,
  SFHASH_SHA_3_384 = 1 <<  8,
  SFHASH_SHA_3_512 = 1 <<  9,
  SFHASH_BLAKE3    = 1 << 10,
  SFHASH_FUZZY     = 1 << 11, // ssdeep fuzzy hash
  SFHASH_ENTROPY   = 1 << 12, // Shannon entropy
  SFHASH_QUICK_MD5 = 1 << 13,
  SFHASH_OTHER     = 1 << 31  // any other hash type
} SFHASH_HashAlgorithm;

// Returns a name string corresponding to the given hash type
const char* sfhash_hash_name(SFHASH_HashAlgorithm hash_type);

// Returns the byte length of the given hash type
uint32_t sfhash_hash_length(SFHASH_HashAlgorithm hash_type);

/******************************************************************************
  Hash set and size set functions
******************************************************************************/

struct SFHASH_HashSet;

/*
 *  Union of two hashsets
 *
 * out is a pointer to the buffer used by the resulting hashset; out must
 * be large enough to hold the result, which could be as much as sum of the
 * size of the hashset header and the sizes of the two hashsets.
 *
 * out_name is the name of the resulting hashset
 *
 * out_desc is the description of the resulting hashset
 *
 * Returns the union hashset, or null on error and sets err to nonnull.
 */
SFHASH_HashSet* sfhash_union_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  const char* out_name,
  const char* out_desc,
  SFHASH_Error** err
);

/*
 * Intersection of two hashsets
 *
 * out is a pointer to the buffer used by the resulting hashset; out must
 * be large enough to hold the result, which could be as much as the sum of
 * the size of the hashset header and size of the larger of the two hashsets.
 *
 * out_name is the name of the resulting hashset
 *
 * out_desc is the description of the resulting hashset
 *
 * Returns the intersection of two hashsets, or null on error and sets err to
 * nonnull.
 */
SFHASH_HashSet* sfhash_intersect_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  const char* out_name,
  const char* out_desc,
  SFHASH_Error** err
);

/*
 * Difference of two hashsets
 *
 * out is a pointer to the buffer used by the resulting hashset; out must
 * be large enough to hold the result, which could be as much as the sum of
 * the size of the hashset header and the size of left hashset.
 *
 * out_name is the name of the resulting hashset
 *
 * out_desc is the description of the resulting hashset
 *
 * Returns the difference of two hashsets, or null on error and sets err to
 * nonnull.
 */
SFHASH_HashSet* sfhash_difference_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  const char* out_name,
  const char* out_desc,
  SFHASH_Error** err
);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */
