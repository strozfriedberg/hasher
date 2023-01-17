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
 * Returns the name of a hashset.
 */
const char* sfhash_hashset_name(const SFHASH_Hashset* hset);

/*
 * Returns the description of a hashset.
 */
const char* sfhash_hashset_description(const SFHASH_Hashset* hset);

/*
 * Returns the ISO-8601 timestamp of a hashset.
 */
const char* sfhash_hashset_timestamp(const SFHASH_Hashset* hset);

/*
 * Returns the SHA2-256 hash of the hashset data.
 *
 * The hash is produced from the hset file from offset 40 to the end.
 */
const void* sfhash_hashset_sha2_256(const SFHASH_Hashset* hset);

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
 * Get the number of hashes in the hashset with the given index.
 */
uint64_t sfhash_hashset_count(
  const SFHASH_Hashset* hset,
  size_t tidx
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

struct SFHASH_HashsetBuildCtx;

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

void sfhash_hashset_builder_add_record(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record
);

void sfhash_hashset_builder_add_hash(
  SFHASH_HashsetBuildCtx* bctx,
  const void* hash,
  size_t length
);

uint64_t sfhash_hashset_builder_write(
  SFHASH_HashsetBuildCtx* bctx,
  SFHASH_Error** err
);

void sfhash_hashset_builder_destroy(SFHASH_HashsetBuildCtx* bctx);

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_union_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_intersect_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_subtract_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* temp_dir,
  SFHASH_Error** err
);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_HASHSET_H_ */
