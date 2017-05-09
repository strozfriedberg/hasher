#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum SFHASH_HashAlgorithms {
  MD5    = 1 << 0,
  SHA1   = 1 << 1,
  SHA256 = 1 << 2
};

typedef struct SFHASH_HashValues {
  uint8_t md5[16],
          sha1[20],
          sha256[32];
} SFHASH_HashValues;

struct SFHASH_Hasher;

// hashAlgs a bitwise-or of desired SFHASH_HashAlgorithms
SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs);

SFHASH_Hasher* sfhash_clone_hasher(const SFHASH_Hasher* hasher);

// update the hash(es) with more data
void sfhash_update_hasher(SFHASH_Hasher* hasher, const void* beg, const void* end);

void sfhash_get_hashes(SFHASH_Hasher* hasher, SFHASH_HashValues* out_hashes);

void sfhash_reset_hasher(SFHASH_Hasher* hasher);

void sfhash_destroy_hasher(SFHASH_Hasher* hasher);

struct SFHASH_FileMatcher;

struct LG_Error;

// Input is a three-column tab-separated UTF-8 text file, where each line
// is of the form:
//
//  Filename\tFilesize\tSHA1\n
//
SFHASH_FileMatcher* sfhash_create_matcher(const char* beg, const char* end, LG_Error** err);

// returns nonzero if the given file size occurs in the hash set
int sfhash_matcher_has_size(const SFHASH_FileMatcher* matcher, uint64_t size);

// returns nonzero if the given file size and hash occur in the hash set
int sfhash_matcher_has_hash(const SFHASH_FileMatcher* matcher, uint64_t size, const uint8_t* sha1);

// returns nonzero if the given filename (in UTF-8) matches the hash set
int sfhash_matcher_has_filename(const SFHASH_FileMatcher* matcher, const char* filename);

// returns the size in bytes of the buffer for sfhash_write_binary_matcher
int sfhash_matcher_size(const SFHASH_FileMatcher* matcher);

// serializes the matcher to a buffer
void sfhash_write_binary_matcher(const SFHASH_FileMatcher* matcher, void* buf);

// unserizalizes the matcher from a buffer
SFHASH_FileMatcher* sfhash_read_binary_matcher(const void* beg, const void* end);

void sfhash_destroy_matcher(SFHASH_FileMatcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */

