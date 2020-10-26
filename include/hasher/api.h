#ifndef HASHER_C_API_H_
#define HASHER_C_API_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 Hash types
******************************************************************************/

// Bit flags for specifying hash algorithms
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
  SFHASH_BLAKE3    = 1 << 10,
  SFHASH_FUZZY     = 1 << 11, // ssdeep fuzzy hash
  SFHASH_ENTROPY   = 1 << 12, // Shannon entropy
  SFHASH_QUICK_MD5 = 1 << 13,
  SFHASH_OTHER     = 1 << 31  // any other hash type
} SFHASH_HashAlgorithm;

// Returns a name string corresponding to the given hash type
const char* sfhash_hash_name(SFHASH_HashAlgorithm hash_type);

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

/******************************************************************************
  Hash set and size set functions
******************************************************************************/

struct SFHASH_HashSet;
struct SFHASH_SizeSet;

// Metadata from the hashset file header
typedef struct {
  uint64_t version;               // file format version
  SFHASH_HashAlgorithm hash_type; // type of hash in this hashset
  uint64_t hash_length;           // length of hash in this hashset
  uint64_t flags;                 // flags; unused at present
  uint64_t hashset_size;          // number of hashes in hashset
  uint64_t hashset_off;           // offset of hashes in hashset file
  uint64_t sizes_off;             // offset of sizes in hashset file
  uint64_t radius;                // max delta of any hash from expected index
  uint8_t hashset_sha256[32];     // SHA-2-256 of hash data only
  char* hashset_name;             // name of hashset
  char* hashset_time;             // ISO 8601 timestamp of hashset
  char* hashset_desc;             // description of hashset
} SFHASH_HashSetInfo;

/*
 * Load hashset metadata
 *
 * Returns null on error and sets err to nonnull.
 */
SFHASH_HashSetInfo* sfhash_load_hashset_info(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

/*
 * Free hashset metadata
 */
void sfhash_destroy_hashset_info(SFHASH_HashSetInfo* hsinfo);

/*
 * Load a hashset
 *
 * The buffer [beg, end) is used directly and the caller remains responsible
 * for freeing it.
 *
 * Returns null on error and sets err to nonnull.
 */
SFHASH_HashSet* sfhash_load_hashset(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

/*
 * Get the metadata for a hashset
 */
const SFHASH_HashSetInfo* sfhash_info_for_hashset(const SFHASH_HashSet* hset);

/*
 * Check if a given hash is contained in a hashset
 */
bool sfhash_lookup_hashset(const SFHASH_HashSet* hset, const void* hash);

/*
 * Free a hashset
 *
 * This does not free the buffer containing the hashset data; the caller
 * remains responsible for freeing that.
 */
void sfhash_destroy_hashset(SFHASH_HashSet* hset);

/*
 *  Union of two hashsets
 *
 * out is a pointer to the buffer used by the resulting hashset; out must
 * be large enough to hold the result, which could be as much as sum of the
 * size of the hashset header and the sizes of the two hashsets.
 *
 * out_name is the name of the resulting hashset
 *
 * out_desc is the description of the resulting hashset
 *
 * Returns the union hashset, or null on error and sets err to nonnull.
 */
SFHASH_HashSet* sfhash_union_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  const char* out_name,
  const char* out_desc,
  SFHASH_Error** err
);

/*
 * Intersection of two hashsets
 *
 * out is a pointer to the buffer used by the resulting hashset; out must
 * be large enough to hold the result, which could be as much as the sum of
 * the size of the hashset header and size of the larger of the two hashsets.
 *
 * out_name is the name of the resulting hashset
 *
 * out_desc is the description of the resulting hashset
 *
 * Returns the intersection of two hashsets, or null on error and sets err to
 * nonnull.
 */
SFHASH_HashSet* sfhash_intersect_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  const char* out_name,
  const char* out_desc,
  SFHASH_Error** err
);

/*
 * Difference of two hashsets
 *
 * out is a pointer to the buffer used by the resulting hashset; out must
 * be large enough to hold the result, which could be as much as the sum of
 * the size of the hashset header and the size of left hashset.
 *
 * out_name is the name of the resulting hashset
 *
 * out_desc is the description of the resulting hashset
 *
 * Returns the difference of two hashsets, or null on error and sets err to
 * nonnull.
 */
SFHASH_HashSet* sfhash_difference_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  const char* out_name,
  const char* out_desc,
  SFHASH_Error** err
);

/*
 * Load a sizeset
 *
 * Returns null on error and sets err to nonnull.
 */
SFHASH_SizeSet* sfhash_load_sizeset(
  SFHASH_HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

/*
 * Free a sizeset
 */
void sfhash_destroy_sizeset(SFHASH_SizeSet* sset);

/*
 * Check if a given size is contained in a sizeset
 */
bool sfhash_lookup_sizeset(const SFHASH_SizeSet* sset, uint64_t size);


/******************************************************************************
  Hex encoding
******************************************************************************/

// Converts len bytes of src to a hexadecimal string dest.
// The length of dest will be 2*len.
void sfhash_hex(char* dest, const void* src, size_t len);

// Converts a hexadecimal string src of length len to bytes dest.
// Returns true on success, false on bad input (either src had a
// character not in [0-9A-Za-z] or src had an odd length).
bool sfhash_unhex(uint8_t* dest, const char* src, size_t len);


/******************************************************************************
  Fuzzy matching
******************************************************************************/

/*
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
  const void* beg,
  const void* end
);

SFHASH_FuzzyResult* sfhash_fuzzy_matcher_compare(
  SFHASH_FuzzyMatcher* matcher,
  const void* beg,
  const void* end
);

size_t sfhash_fuzzy_result_count(const SFHASH_FuzzyResult* result);

const char* sfhash_fuzzy_result_filename(
  const SFHASH_FuzzyResult* result,
  size_t i
);

const char* sfhash_fuzzy_result_query_filename(const SFHASH_FuzzyResult* result);

int sfhash_fuzzy_result_score(const SFHASH_FuzzyResult* result, size_t i);

void sfhash_destroy_fuzzy_match(SFHASH_FuzzyResult* result);

void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */
