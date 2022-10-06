#pragma once

#include "hasher/hashset.h"

#include <cstdint>

class HashSetData {
public:
  virtual ~HashSetData() {}

  virtual bool contains(const uint8_t* hash) const = 0;

  virtual const uint8_t* data() const = 0;
};

HashSetData* load_hashset_data(
  const SFHASH_Hashset* hset,
  size_t tidx
);
