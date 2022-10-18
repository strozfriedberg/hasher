#ifndef HASHER_COMMON_H_
#define HASHER_COMMON_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 Digest algorithms
******************************************************************************/

// Bit flags for specifying hash algorithms
typedef enum {
  SFHASH_MD5       = 1 << 0,
  SFHASH_SHA_1     = 1 << 1,
  SFHASH_SHA_2_224 = 1 << 2,
  SFHASH_SHA_2_256 = 1 << 3,
  SFHASH_SHA_2_384 = 1 << 4,
  SFHASH_SHA_2_512 = 1 << 5,
  SFHASH_SHA_3_224 = 1 << 6,
  SFHASH_SHA_3_256 = 1 << 7,
  SFHASH_SHA_3_384 = 1 << 8,
  SFHASH_SHA_3_512 = 1 << 9,
  SFHASH_BLAKE3    = 1 << 10,
  SFHASH_FUZZY     = 1 << 11, // ssdeep fuzzy hash
  SFHASH_ENTROPY   = 1 << 12, // Shannon entropy
  SFHASH_SIZE      = 1 << 13, // file size
  SFHASH_QUICK_MD5 = 1 << 14  // TOOD: Can we kill this?
} SFHASH_HashAlgorithm;

// Returns a name string corresponding to the given hash type
const char* sfhash_hash_name(SFHASH_HashAlgorithm hash_type);

// Returns the enum corresponding to the given hash name string
SFHASH_HashAlgorithm sfhash_hash_type(const char* name);

// Returns the byte length of the given hash type
uint32_t sfhash_hash_length(SFHASH_HashAlgorithm hash_type);

/******************************************************************************
 Error handling
******************************************************************************/

struct SFHASH_Error {
  char* message;
};

// Frees an error struct
void sfhash_free_error(SFHASH_Error* err);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_COMMON_H_ */
