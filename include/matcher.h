#pragma once

#include <vector>

#include <lightgrep/api.h>

#include "util.h"

struct SFHASH_FileMatcher {
  std::vector<std::pair<size_t, sha1_t>> table;
  std::unique_ptr<PatternMapHandle, decltype(lg_destroy_pattern_map)&> pmap;
  std::unique_ptr<ProgramHandle, decltype(lg_destroy_program)&> prog;
};

SFHASH_FileMatcher load_hashset(const char* beg, const char* end);
