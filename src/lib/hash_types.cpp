#include "hash_types.h"

const char* sfhash_hash_name(SFHASH_HashAlgorithm hash_type) {
  return hash_name(hash_type);
}

uint32_t sfhash_hash_length(SFHASH_HashAlgorithm hash_type) {
  return hash_length(hash_type);
}
