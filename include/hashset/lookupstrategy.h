#pragma once

#include <cstddef>
#include <cstdint>

struct SFHASH_Hashset;

class LookupStrategy {
public:
  virtual ~LookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const = 0;
};
