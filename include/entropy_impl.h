#pragma once

#include <cstdint>

struct SFHASH_Entropy {
  uint64_t count[256] = {0};
};
