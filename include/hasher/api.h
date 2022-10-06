#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <hasher/common.h>

#ifdef __cplusplus
extern "C" {
#endif

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
