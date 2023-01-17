#include "hash_types.h"

#include <algorithm>
#include <map>
#include <string>

const char* sfhash_hash_name(SFHASH_HashAlgorithm type) {
  return hash_name(type);
}

SFHASH_HashAlgorithm sfhash_hash_type(const char* name) {
  return hash_type(name);
}

uint32_t sfhash_hash_length(SFHASH_HashAlgorithm type) {
  return hash_length(type);
}

// The names are lowercased with hyphens and underscores removed. This gives
// maximum flexibility for user input without introducing ambiguity.
const std::map<std::string, SFHASH_HashAlgorithm> NAMES_TO_TYPES{
  { "md5",       SFHASH_MD5 },
  { "sha1",      SFHASH_SHA_1 },
  { "sha2224",   SFHASH_SHA_2_224 },
  { "sha2256",   SFHASH_SHA_2_256 },
  { "sha2384",   SFHASH_SHA_2_384 },
  { "sha2512",   SFHASH_SHA_2_512 },
  { "sha3224",   SFHASH_SHA_3_224 },
  { "sha3256",   SFHASH_SHA_3_256 },
  { "sha3384",   SFHASH_SHA_3_384 },
  { "sha3512",   SFHASH_SHA_3_512 },
  { "blake3",    SFHASH_BLAKE3 },
  { "fuzzy",     SFHASH_FUZZY },
  { "entropy",   SFHASH_ENTROPY },
  { "size",      SFHASH_SIZE },
  { "quick md5", SFHASH_QUICK_MD5 }
};

SFHASH_HashAlgorithm hash_type(const char* name) {
  std::string norm(name);

  // remove all the hyphens and underscores
  norm.erase(std::remove_if(
    norm.begin(), norm.end(),
    [](char c) { return c == '-' || c == '_'; }
  ), norm.end());

  // lowercase the hash name
  std::transform(
    norm.begin(), norm.end(), norm.begin(),
    [](unsigned char c) { return std::tolower(c); }
  );

  const auto i = NAMES_TO_TYPES.find(norm);
  return i != NAMES_TO_TYPES.end() ? i->second : SFHASH_INVALID;
}
