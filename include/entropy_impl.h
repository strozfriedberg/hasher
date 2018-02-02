#pragma once

#include <cstdint>

struct SFHASH_Entropy {
  uint64_t hist[256] = {0};
};
