#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <cstddef>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum SFHASH_HashAlgorithms {
  MD5       = 1 << 0,
  SHA1      = 1 << 1,
  SHA256    = 1 << 2,
  FUZZY     = 1 << 3,
  ENTROPY   = 1 << 4,
  QUICK_MD5 = 1 << 5
};

typedef struct SFHASH_HashValues {
  uint8_t Md5[16];
  uint8_t Sha1[20];
  uint8_t Sha256[32];
  uint8_t Fuzzy[148];
  uint8_t QuickMd5[16];
  double Entropy;
} SFHASH_HashValues;

struct SFHASH_Hasher;

// hashAlgs a bitwise-or of desired SFHASH_HashAlgorithms
SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs);

SFHASH_Hasher* sfhash_clone_hasher(const SFHASH_Hasher* hasher);

// update the hash(es) with more data
void sfhash_update_hasher(SFHASH_Hasher* hasher, const void* beg, const void* end);

// optional
void sfhash_hasher_set_total_input_length(SFHASH_Hasher* hasher, uint64_t total_fixed_length);

void sfhash_get_hashes(SFHASH_Hasher* hasher, SFHASH_HashValues* out_hashes);

void sfhash_reset_hasher(SFHASH_Hasher* hasher);

void sfhash_destroy_hasher(SFHASH_Hasher* hasher);

struct SFHASH_FileMatcher;

struct SFHASH_FuzzyMatcher;

struct SFHASH_FuzzyResult;

struct LG_Error;

// Input is a three-column tab-separated UTF-8 text file, where each line
// is of the form:
//
//  Filename\tFilesize\tSHA1\n
//
SFHASH_FileMatcher* sfhash_create_matcher(const char* beg, const char* end, LG_Error** err);

SFHASH_FileMatcher* sfhash_create_matcher_binary(const char* beg, const char* end);

// returns nonzero if the given file size occurs in the hash set
int sfhash_matcher_has_size(const SFHASH_FileMatcher* matcher, uint64_t size);

// returns nonzero if the given file hash occurrs in the hash set
int sfhash_matcher_has_hash(const SFHASH_FileMatcher* matcher, const uint8_t* sha1);

// returns nonzero if the given filename (in UTF-8) matches the hash set
int sfhash_matcher_has_filename(const SFHASH_FileMatcher* matcher, const char* filename);

// returns the size in bytes of the buffer for sfhash_write_binary_matcher
int sfhash_matcher_size(const SFHASH_FileMatcher* matcher);

// serializes the matcher to a buffer
void sfhash_write_binary_matcher(const SFHASH_FileMatcher* matcher, void* buf);

// unserizalizes the matcher from a buffer
SFHASH_FileMatcher* sfhash_read_binary_matcher(const void* beg, const void* end);

void sfhash_destroy_matcher(SFHASH_FileMatcher* matcher);

// Fuzzy Matching!
// Input is the ssdeep CSV file format version 1.1
// The first line is the header
// ssdeep,1.1--blocksize:hash:hash,filename
//
// Each line after represents the fuzzy hash of one file:
// blocksize:hash:hash,"filename"
// The filename must be quoted and \-escaped.

SFHASH_FuzzyMatcher* sfhash_create_fuzzy_matcher(const char* beg, const char* end);

const SFHASH_FuzzyResult* sfhash_fuzzy_matcher_compare(SFHASH_FuzzyMatcher* matcher,
                                                       const char* beg,
                                                       const char* end);
size_t sfhash_fuzzy_result_count(const SFHASH_FuzzyResult* result);
const char* sfhash_fuzzy_result_filename(const SFHASH_FuzzyResult* result, size_t i);
const char* sfhash_fuzzy_result_query_filename(const SFHASH_FuzzyResult* result);
int sfhash_fuzzy_result_score(const SFHASH_FuzzyResult* result, size_t i);
void sfhash_fuzzy_destroy_match(const SFHASH_FuzzyResult* result);

void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */
