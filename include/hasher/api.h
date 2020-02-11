#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Hash set functions
 */

struct HashSet;
struct SizeSet;

typedef enum {
  SF_HASH_OTHER     =  0,
  SF_HASH_MD5       =  1,
  SF_HASH_SHA_1     =  2,
  SF_HASH_SHA_2_224 =  3,
  SF_HASH_SHA_2_256 =  4,
  SF_HASH_SHA_2_384 =  5,
  SF_HASH_SHA_2_512 =  6,
  SF_HASH_SHA_3_224 =  7,
  SF_HASH_SHA_3_256 =  8,
  SF_HASH_SHA_3_384 =  9,
  SF_HASH_SHA_3_512 = 10
} SF_HASH_TYPE_ENUM;

struct HashSetInfo {
  uint64_t version;
  SF_HASH_TYPE_ENUM hash_type;
  uint64_t hash_length;
  uint64_t flags;
  uint64_t hashset_size;
  uint64_t hashset_off;
  uint64_t sizes_off;
  uint64_t radius;
  uint8_t hashset_sha256[32];
  char* hashset_name;
  char* hashset_time;
  char* hashset_desc;
};

struct HasherError {
  char* message;
};

void sf_free_hashset_error(HasherError* err);

HashSetInfo* sf_load_hashset_info(
  const void* beg,
  const void* end,
  HasherError** err
);

void sf_destroy_hashset_info(HashSetInfo* hsinfo);

HashSet* sf_load_hashset(
  const HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  bool shared,
  HasherError** err
);

void sf_destroy_hashset(HashSet* hset);

const char* sf_hash_type_name(SF_HASH_TYPE_ENUM hash_type);

bool sf_lookup_hashset(const HashSet* hset, const void* hash);

SizeSet* sf_load_sizeset(
  HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  bool shared,
  HasherError** err
);

void sf_destroy_sizeset(SizeSet* sset);

bool sf_lookup_sizeset(const SizeSet* sset, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */

