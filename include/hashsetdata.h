#pragma once

#include "hasher/api.h"

#include <algorithm>
#include <array>

class HashSetData {
public:
  virtual ~HashSetData() {}

  virtual bool contains(const uint8_t* hash) const = 0;

  virtual const uint8_t* data() const = 0;
};

HashSetData* load_hashset_data(
  const SFHASH_HashSetInfo* hsinfo,
  const void* beg,
  const void* end
);

uint32_t expected_index(const uint8_t* h, uint32_t set_size);

template <size_t HashLength>
uint32_t compute_radius(
  const std::array<uint8_t, HashLength>* beg,
  const std::array<uint8_t, HashLength>* end
)
{
  const uint32_t count = end - beg;
  int64_t max_delta = 0;
  for (uint32_t i = 0; i < count; ++i) {
    max_delta = std::max(
      max_delta,
      std::abs((int64_t)i - expected_index(beg[i].data(), count))
    );
  }
  return max_delta;
}
