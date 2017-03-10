#pragma once

#include <utility>
#include <vector>

#include "util.h"

std::vector<std::pair<size_t, sha1_t>> load_hashset(const char* beg, const char* end);
