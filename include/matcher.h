#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <lightgrep/api.h>

#include "util.h"

struct SFHASH_FileMatcher {
  std::vector<std::pair<uint64_t, sha1_t>> table;
  std::unique_ptr<ProgramHandle, decltype(lg_destroy_program)&> prog;
};

std::unique_ptr<SFHASH_FileMatcher> load_hashset(const char* beg, const char* end, LG_Error** err);
