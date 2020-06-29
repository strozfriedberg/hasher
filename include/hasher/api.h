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

struct SFHASH_HashSetHolder;
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

// Load hashset metadata
// Returns null on error and sets err to nonnull
SFHASH_HashSetInfo* sfhash_load_hashset_info(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

// Frees hashset metadata
void sfhash_destroy_hashset_info(SFHASH_HashSetInfo* hsinfo);

// Loads a hashset
// The data is copied if shared is false; used directly if shared is true,
// and caller remains responsible for freeing it.
// Returns null on error and sets err to nonnull
SFHASH_HashSet* sfhash_load_hashset(
  const SFHASH_HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  bool shared,
  SFHASH_Error** err
);

// Frees a hashset
void sfhash_destroy_hashset(SFHASH_HashSet* hset);

// Checks if a given hash is contained in a hashset
bool sfhash_lookup_hashset(const SFHASH_HashSet* hset, const void* hash);



SFHASH_HashSetHolder* sfhash_load_hashset_holder(
  const void* beg,
  const void* end,
  bool shared,
  SFHASH_Error** err
);

const SFHASH_HashSetInfo* sfhash_info_from_holder(const SFHASH_HashSetHolder* hset);

bool sfhash_lookup_hashset_holder(const SFHASH_HashSetHolder* hset, const void* hash);

void sfhash_destroy_hashset_holder(SFHASH_HashSetHolder* hset);

SFHASH_HashSetHolder* sfhash_union_hashsets(const SFHASH_HashSetHolder* a, const SFHASH_HashSetHolder* b, void* out, bool shared);

SFHASH_HashSetHolder* sfhash_intersect_hashsets(const SFHASH_HashSetHolder* a, const SFHASH_HashSetHolder* b, void* out, bool shared);

SFHASH_HashSetHolder* sfhash_difference_hashsets(const SFHASH_HashSetHolder* a, const SFHASH_HashSetHolder* b, void* out, bool shared);



// Loads a sizeset
// Returns null on error and sets err to nonnull
SFHASH_SizeSet* sfhash_load_sizeset(
  SFHASH_HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

// Frees a sizeset
void sfhash_destroy_sizeset(SFHASH_SizeSet* sset);

// Checks if a given size is contained in a sizeset
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

const SFHASH_FuzzyResult* sfhash_fuzzy_matcher_compare(
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

void sfhash_destroy_fuzzy_match(const SFHASH_FuzzyResult* result);

void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);


/******************************************************************************
  Matcher
******************************************************************************/

/*
 * Input is a three-column tab-separated UTF-8 text file, where each line
 * is of the form:
 *
 *  Filename\tFilesize\tHash\n
 *
 */

struct SFHASH_FileMatcher;

SFHASH_FileMatcher* sfhash_create_matcher(
  const void* beg,
  const void* end,
  SFHASH_Error** err
);

// returns nonzero if the given file size occurs in the hash set
bool sfhash_matcher_has_size(const SFHASH_FileMatcher* matcher, uint64_t size);

// returns nonzero if the given file hash occurrs in the hash set
bool sfhash_matcher_has_hash(const SFHASH_FileMatcher* matcher, const uint8_t* sha1);

// returns nonzero if the given filename (in UTF-8) matches the hash set
bool sfhash_matcher_has_filename(const SFHASH_FileMatcher* matcher, const char* filename);

void sfhash_destroy_matcher(SFHASH_FileMatcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_C_API_H_ */
