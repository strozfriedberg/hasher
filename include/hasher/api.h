#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Hash set functions
 */

struct HashSet;

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

const char* sf_hash_type(const HashSet* hset);

size_t sf_hash_length(const HashSet* hset);

int sf_lookup_hashset(const HashSet* hset, const void* hash);

void sf_free_hashset_error(HasherError* err);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */

