#pragma once

#include "hasher/api.h"

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
