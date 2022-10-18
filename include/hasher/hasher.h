#ifndef HASHER_HASHER_H_
#define HASHER_HASHER_H_

#include <stdint.h>

#include <hasher/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 Hashing functions
******************************************************************************/

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
  uint8_t Blake3[32];
  uint8_t Fuzzy[148];
  uint8_t QuickMd5[16];
  double Entropy;
};

struct SFHASH_Hasher;

// Creates a hasher for the given hash types.
// hashAlgs is the bitwise OR of SFHASH_HashAlgorithm flags
SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs);

// Clones a hasher
SFHASH_Hasher* sfhash_clone_hasher(const SFHASH_Hasher* hasher);

// Adds [beg, end) to the hasher digest
void sfhash_update_hasher(
  SFHASH_Hasher* hasher,
  const void* beg,
  const void* end
);

// Set the expected bytes of input to be hashed
// This is a no-op for all hash types except fuzzy.
void sfhash_hasher_set_total_input_length(
  SFHASH_Hasher* hasher,
  uint64_t total_fixed_length
);

// Stores the requested hashes in out_hashes
void sfhash_get_hashes(
  SFHASH_Hasher* hasher,
  SFHASH_HashValues* out_hashes
);

// Resets a hasher to its initial state, ready to hash anew
void sfhash_reset_hasher(SFHASH_Hasher* hasher);

// Frees a hasher
void sfhash_destroy_hasher(SFHASH_Hasher* hasher);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_HASHER_H_ */
