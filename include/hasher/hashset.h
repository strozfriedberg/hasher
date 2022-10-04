#ifndef HASHER_HASHSET_H_
#define HASHER_HASHSET_H_

#include <stdbool.h>
#include <stddef.h>

#include <hasher/common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  X_SFHASH_SIZE,
  X_SFHASH_MD5,
  X_SFHASH_SHA_1,
  X_SFHASH_SHA_2_224,
  X_SFHASH_SHA_2_256,
  X_SFHASH_SHA_2_384,
  X_SFHASH_SHA_2_512,
  X_SFHASH_SHA_3_224,
  X_SFHASH_SHA_3_256,
  X_SFHASH_SHA_3_384,
  X_SFHASH_SHA_3_512,
  X_SFHASH_BLAKE3,
//  SFHASH_FUZZY,
  X_SFHASH_ENTROPY,
//  SFHASH_QUICK_MD5,
  X_SFHASH_OTHER = 0xFFFF // any other hash type
} SFHASH_HashsetType;

struct SFHASH_Hashset;

/*
 * Load a hashset
 *
 * The buffer [beg, end) is used directly and the caller remains responsible
 * for freeing it.
 *
 * Returns null on error and sets err to nonnull.
 */
SFHASH_Hashset* x_sfhash_load_hashset(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

/*
 * Free a hashset
 */
void x_sfhash_destroy_hashset(SFHASH_Hashset* hset);

/*
 * Get hashset data index for the given hash type.
 *
 * Returns the index, or -1 if the is no data for the specified type.
 */
int sfhash_hashset_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashsetType htype
);

/*
 *  Check if the given hash is contained in a hashset.
 *
 *  The type index is the index returned by sfhash_hashset_index_for_type.
 */
bool x_sfhash_hashset_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
);

struct SFHASH_HashsetRecordRange {
  size_t beg;
  size_t end;
};

const SFHASH_HashsetRecordRange x_sfhash_hashset_records_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
);

struct SFHASH_HashsetRecord;

const void* x_sfhash_hashset_record_for_hash(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t ridx
);

const void* x_sfhash_hashset_record_field(
  const SFHASH_HashsetRecord* rec,
  SFHASH_HashsetType htype
);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_HASHSET_H_ */
