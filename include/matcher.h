#pragma once

#include <memory>
#include <utility>
#include <unordered_set>
#include <vector>

#include <lightgrep/api.h>

#include "util.h"

struct SFHASH_FileMatcher {
  std::unordered_set<uint64_t> Sizes;
  std::vector<sha1_t> Hashes;
  std::unique_ptr<ProgramHandle, decltype(lg_destroy_program)&> Prog;
  size_t HashRadius;
};

std::unique_ptr<SFHASH_FileMatcher> load_hashset(const char* beg, const char* end, LG_Error** err);

//std::unique_ptr<SFHASH_FileMatcher> load_hashset_binary(const char* beg, const char* end);
