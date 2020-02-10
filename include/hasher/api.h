#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Hash set functions
 */

struct HashSet;

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

struct HasherError {
  char* message;
};

HashSet* sf_create_hashset(
  const char* htype,
  size_t hlen,
  const char* name,
  const char* desc,
  size_t radius,
  const void* beg,
  const void* end,
  bool shared
);

HashSet* sf_load_hashset_header(
  const void* beg,
  const void* end,
  HasherError** err
);

bool sf_load_hashset_data(
  HashSet* hset,
  const void* beg,
  const void* end,
  bool shared,
  HasherError** err
);

void sf_destroy_hashset(HashSet* hset);

const char* sf_hashset_name(const HashSet* hset);

const char* sf_hashset_description(const HashSet* hset);

size_t sf_hashset_size(const HashSet* hset);

SF_HASH_TYPE_ENUM sf_hash_type(const HashSet* hset);

const char* sf_hash_type_name(SF_HASH_TYPE_ENUM hash_type);

size_t sf_hash_length(const HashSet* hset);

int sf_lookup_hashset(const HashSet* hset, const void* hash);

void sf_free_hashset_error(HasherError* err);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */

