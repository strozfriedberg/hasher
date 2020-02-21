#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
  SFHASH_FUZZY     = 1 << 10,
  SFHASH_ENTROPY   = 1 << 11,
  SFHASH_QUICK_MD5 = 1 << 12,
  SFHASH_OTHER     = 1 << 31
} SFHASH_HashAlgorithm;

const char* sfhash_hash_name(SFHASH_HashAlgorithm hash_type);

uint32_t sfhash_hash_length(SFHASH_HashAlgorithm hash_type);

/*
 * Error handling
 */

struct SFHASH_Error {
  char* message;
};

void sfhash_free_error(SFHASH_Error* err);

/*
 * Hashing functions
 */

struct SFHASH_HashValues {
  uint8_t Md5[16];
  uint8_t Sha1[20];
  uint8_t Sha2_224[28];
  uint8_t Sha2_256[32];
  uint8_t Sha2_384[48];
  uint8_t Sha2_512[64];
  uint8_t Sha3_224[28];
  uint8_t Sha3_256[32];
  uint8_t Sha3_384[48];
  uint8_t Sha3_512[64];
  uint8_t Fuzzy[148];
  uint8_t QuickMd5[16];
  double Entropy;
};

struct SFHASH_Hasher;

SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs);

SFHASH_Hasher* sfhash_clone_hasher(const SFHASH_Hasher* hasher);

void sfhash_update_hasher(
  SFHASH_Hasher* hasher,
  const void* beg,
  const void* end
);

void sfhash_hasher_set_total_input_length(
  SFHASH_Hasher* hasher,
  uint64_t total_fixed_length
);

void sfhash_get_hashes(
  SFHASH_Hasher* hasher,
  SFHASH_HashValues* out_hashes
);

void sfhash_reset_hasher(SFHASH_Hasher* hasher);

void sfhash_destroy_hasher(SFHASH_Hasher* hasher);

/*
 *  Hash set and size set functions
 */

struct SFHASH_HashSet;
struct SFHASH_SizeSet;

typedef struct {
  uint64_t version;
  SFHASH_HashAlgorithm hash_type;
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
} SFHASH_HashSetInfo;

SFHASH_HashSetInfo* sfhash_load_hashset_info(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

void sfhash_destroy_hashset_info(SFHASH_HashSetInfo* hsinfo);

SFHASH_HashSet* sfhash_load_hashset(
  const SFHASH_HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  bool shared,
  SFHASH_Error** err
);

void sfhash_destroy_hashset(SFHASH_HashSet* hset);

bool sfhash_lookup_hashset(const SFHASH_HashSet* hset, const void* hash);

SFHASH_SizeSet* sfhash_load_sizeset(
  SFHASH_HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

void sfhash_destroy_sizeset(SFHASH_SizeSet* sset);

bool sfhash_lookup_sizeset(const SFHASH_SizeSet* sset, uint64_t size);

/*
 *  Fuzzy matching
 *
 *  Input is the ssdeep CSV file format version 1.1
 *  The first line is the header
 *  ssdeep,1.1--blocksize:hash:hash,filename
 *
 *  Each line after represents the fuzzy hash of one file:
 *  blocksize:hash:hash,"filename"
 * The filename must be quoted and \-escaped.
 */

struct SFHASH_FuzzyMatcher;

struct SFHASH_FuzzyResult;

SFHASH_FuzzyMatcher* sfhash_create_fuzzy_matcher(
  const char* beg,
  const char* end
);

const SFHASH_FuzzyResult* sfhash_fuzzy_matcher_compare(
  SFHASH_FuzzyMatcher* matcher,
  const char* beg,
  const char* end
);

size_t sfhash_fuzzy_result_count(const SFHASH_FuzzyResult* result);

const char* sfhash_fuzzy_result_filename(
  const SFHASH_FuzzyResult* result,
  size_t i
);

const char* sfhash_fuzzy_result_query_filename(const SFHASH_FuzzyResult* result);

int sfhash_fuzzy_result_score(const SFHASH_FuzzyResult* result, size_t i);

void sfhash_destroy_fuzzy_match(const SFHASH_FuzzyResult* result);

void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);

/*
 * Matcher
 *
 * Input is a three-column tab-separated UTF-8 text file, where each line
 * is of the form:
 *
 *  Filename\tFilesize\tHash\n
 *
 */

struct SFHASH_FileMatcher;

SFHASH_FileMatcher* sfhash_create_matcher(
  const char* beg,
  const char* end,
  SFHASH_Error** err
);

// returns nonzero if the given file size occurs in the hash set
int sfhash_matcher_has_size(const SFHASH_FileMatcher* matcher, uint64_t size);

// returns nonzero if the given file hash occurrs in the hash set
int sfhash_matcher_has_hash(const SFHASH_FileMatcher* matcher, const uint8_t* sha1);

// returns nonzero if the given filename (in UTF-8) matches the hash set
int sfhash_matcher_has_filename(const SFHASH_FileMatcher* matcher, const char* filename);

void sfhash_destroy_matcher(SFHASH_FileMatcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */

