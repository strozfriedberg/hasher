#include "hasher.h"

using Matcher = SFHASH_FileMatcher;

Matcher* sfhash_create_matcher(const char* beg, const char* end, LG_Error** err) {
  return nullptr;
}

int sfhash_matcher_has_size(Matcher* matcher, uint64_t size) {
  return 0;
}

int sfhash_matcher_has_hash(Matcher* matcher, uint64_t size, const uint8_t sha1[20]) {
  return 0;
}

int sfhash_matcher_has_filename(Matcher* matcher, const char* filename) {
  return 0;
}

int sfhash_matcher_size(Matcher* matcher) {
  return 0;
}

void sfhash_write_binary_matcher(Matcher* matcher, void* buf) {
}

Matcher* sfhash_read_binary_matcher(const void* beg, const void* end) {
  return nullptr; 
}

void sfhash_destroy_matcher(SFHASH_FileMatcher* matcher) {
}
