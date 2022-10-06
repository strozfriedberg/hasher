#pragma once

#include "hasher/api.h"
#include "hasher/hasher.h"

#include <limits>

//
// Hash enum mappings
//

constexpr const char* hash_name(uint64_t hash_type) {
  switch (hash_type) {
  case SFHASH_MD5:       return "MD5";
  case SFHASH_SHA_1:     return "SHA-1";
  case SFHASH_SHA_2_224: return "SHA-2-224";
  case SFHASH_SHA_2_256: return "SHA-2-256";
  case SFHASH_SHA_2_384: return "SHA-2-384";
  case SFHASH_SHA_2_512: return "SHA-2-512";
  case SFHASH_SHA_3_224: return "SHA-3-224";
  case SFHASH_SHA_3_256: return "SHA-3-256";
  case SFHASH_SHA_3_384: return "SHA-3-384";
  case SFHASH_SHA_3_512: return "SHA-3-512";
  case SFHASH_FUZZY:     return "Fuzzy";
  case SFHASH_QUICK_MD5: return "Quick MD5";
  default:               return nullptr;
  }
}

constexpr uint64_t hash_length(SFHASH_HashAlgorithm hash_type) {
  switch (hash_type) {
  case SFHASH_MD5:       return sizeof(SFHASH_HashValues::Md5);
  case SFHASH_SHA_1:     return sizeof(SFHASH_HashValues::Sha1);
  case SFHASH_SHA_2_224: return sizeof(SFHASH_HashValues::Sha2_224);
  case SFHASH_SHA_2_256: return sizeof(SFHASH_HashValues::Sha2_256);
  case SFHASH_SHA_2_384: return sizeof(SFHASH_HashValues::Sha2_384);
  case SFHASH_SHA_2_512: return sizeof(SFHASH_HashValues::Sha2_512);
  case SFHASH_SHA_3_224: return sizeof(SFHASH_HashValues::Sha3_224);
  case SFHASH_SHA_3_256: return sizeof(SFHASH_HashValues::Sha3_256);
  case SFHASH_SHA_3_384: return sizeof(SFHASH_HashValues::Sha3_384);
  case SFHASH_SHA_3_512: return sizeof(SFHASH_HashValues::Sha3_512);
  case SFHASH_FUZZY:     return sizeof(SFHASH_HashValues::Fuzzy);
  case SFHASH_QUICK_MD5: return sizeof(SFHASH_HashValues::QuickMd5);
  default:               return 0;
  }
}

constexpr size_t hash_member_offset(SFHASH_HashAlgorithm hash_type) {
  switch (hash_type) {
  case SFHASH_MD5:       return offsetof(SFHASH_HashValues, Md5);
  case SFHASH_SHA_1:     return offsetof(SFHASH_HashValues, Sha1);
  case SFHASH_SHA_2_224: return offsetof(SFHASH_HashValues, Sha2_224);
  case SFHASH_SHA_2_256: return offsetof(SFHASH_HashValues, Sha2_256);
  case SFHASH_SHA_2_384: return offsetof(SFHASH_HashValues, Sha2_384);
  case SFHASH_SHA_2_512: return offsetof(SFHASH_HashValues, Sha2_512);
  case SFHASH_SHA_3_224: return offsetof(SFHASH_HashValues, Sha3_224);
  case SFHASH_SHA_3_256: return offsetof(SFHASH_HashValues, Sha3_256);
  case SFHASH_SHA_3_384: return offsetof(SFHASH_HashValues, Sha3_384);
  case SFHASH_SHA_3_512: return offsetof(SFHASH_HashValues, Sha3_512);
  case SFHASH_FUZZY:     return offsetof(SFHASH_HashValues, Fuzzy);
  case SFHASH_ENTROPY:   return offsetof(SFHASH_HashValues, Entropy);
  case SFHASH_QUICK_MD5: return offsetof(SFHASH_HashValues, QuickMd5);
  default:               return std::numeric_limits<size_t>::max();
  }
}
