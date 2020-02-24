#pragma once

#include <memory>
#include <utility>
#include <unordered_set>
#include <vector>

#include <lightgrep/api.h>

#include "util.h"

struct SFHASH_FileMatcher {
  std::unique_ptr<SFHASH_SizeSet, decltype(sfhash_destroy_sizeset)&> Sizes;
  std::unique_ptr<SFHASH_HashSet, decltype(sfhash_destroy_hashset)&> Hashes;
  std::unique_ptr<ProgramHandle, decltype(lg_destroy_program)&> Prog;
};

std::unique_ptr<SFHASH_FileMatcher> load_hashset(const char* beg, const char* end, LG_Error** err);

//std::unique_ptr<SFHASH_FileMatcher> load_hashset_binary(const char* beg, const char* end);
