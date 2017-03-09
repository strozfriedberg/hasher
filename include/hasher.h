#pragma once

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

SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs);

SFHASH_Hasher* sfhash_clone_hasher(const SFHASH_Hasher* hasher);

void sfhash_update_hasher(SFHASH_Hasher* hasher, const void* beg, const void* end);

void sfhash_get_hashes(SFHASH_Hasher* hasher, SFHASH_HashValues* out_hashes);

void sfhash_reset_hasher(SFHASH_Hasher* hasher);

void sfhash_destroy_hasher(SFHASH_Hasher* hasher);

struct SFHASH_FileMatcher;

struct LG_Error;

SFHASH_FileMatcher* sfhash_create_matcher(const uint8_t* beg, const uint8_t* end, LG_Error** err);

int sfhash_matcher_has_size(SFHASH_FileMatcher* matcher, uint64_t size);

int sfhash_matcher_has_hash(SFHASH_FileMatcher* matcher, uint64_t size, uint8_t sha1[20]);

int sfhash_matcher_has_filename(SFHASH_FileMatcher* matcher, const char* filename);

int sfhash_matcher_size(SFHASH_FileMatcher* matcher);

void sfhash_write_binary_matcher(SFHASH_FileMatcher* matcher, void* buf);

SFHASH_FileMatcher* sfhash_read_binary_matcher(void* beg, void* end);

#ifdef __cplusplus
}
#endif