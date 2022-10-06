#pragma once

struct SFHASH_Hashset;

class LookupStrategy {
public:
  virtual ~LookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const = 0;

  virtual const uint8_t* data() const = 0;
};

LookupStrategy* load_lookup_strategy(
  const SFHASH_Hashset* hset,
  size_t tidx
);
