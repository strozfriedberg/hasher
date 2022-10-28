#ifndef HASHER_HASHSET_H_
#define HASHER_HASHSET_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include <hasher/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct SFHASH_Hashset;

/*
 * Load a hashset
 *
 * The buffer [beg, end) is used directly and the caller remains responsible
 * for freeing it.
 *
 * Returns null on error and sets err to nonnull.
 */
SFHASH_Hashset* sfhash_load_hashset(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

/*
 * Free a hashset
 */
void sfhash_destroy_hashset(SFHASH_Hashset* hset);

/*
 * Get hashset data index for the given hash type.
 *
 * Returns the index, or -1 if the is no data for the specified type.
 */
int sfhash_hashset_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashAlgorithm htype
);

/*
 *  Check if the given hash is contained in a hashset.
 *
 *  The type index is the index returned by sfhash_hashset_index_for_type.
 */
bool sfhash_hashset_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
);

struct SFHASH_HashsetRecordRange {
  size_t beg;
  size_t end;
};

const SFHASH_HashsetRecordRange sfhash_hashset_records_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
);

struct SFHASH_HashsetRecord;

const SFHASH_HashsetRecord* sfhash_hashset_record_for_hash(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t ridx
);

int sfhash_hashset_record_field_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashAlgorithm htype
);

const void* sfhash_hashset_record_field(
  const SFHASH_HashsetRecord* rec,
  size_t tidx
);

/*
 *
 */

struct SFHASH_HashsetBuildCtx;

SFHASH_HashsetBuildCtx* sfhash_save_hashset_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length
);

void sfhash_add_hashset_record(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record
);

size_t sfhash_save_hashset_size(
  const SFHASH_HashsetBuildCtx* bctx
);

size_t sfhash_save_hashset_close(
  SFHASH_HashsetBuildCtx* bctx,
  void* out,
  SFHASH_Error** err
);

void sfhash_save_hashset_destroy(SFHASH_HashsetBuildCtx* bctx);

void sfhash_union_hashsets(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  ssize_t (*write_func)(void*, const void*, size_t),
  void* wctx,
  SFHASH_Error** err
);

void sfhash_intersect_hashsets(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  ssize_t (*write_func)(void*, const void*, size_t),
  void* wctx,
  SFHASH_Error** err
);

void sfhash_difference_hashsets(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  ssize_t (*write_func)(void*, const void*, size_t),
  void* wctx,
  SFHASH_Error** err
);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_HASHSET_H_ */
