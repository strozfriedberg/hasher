#pragma once

#include "hashset/basic_ls.h"
#include "hashset/util.h"

#include <algorithm>
#include <array>
#include <limits>

template <size_t HashLength>
class RadiusLookupStrategy: public BasicLookupStrategy<HashLength> {
public:
  RadiusLookupStrategy(
    const void* beg,
    const void* end,
    uint32_t radius
  ):
    BasicLookupStrategy<HashLength>(beg, end), Radius(radius) {}

  virtual ~RadiusLookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const override {
    const size_t exp = expected_index(hash, this->HashesEnd - this->HashesBeg.get());
    return std::binary_search(
      std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp - Radius),
      std::min(this->HashesEnd, this->HashesBeg.get() + exp + Radius + 1),
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }

protected:
  uint32_t Radius;
};

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

template <size_t HashLength>
LookupStrategy* make_radius_lookup_strategy(
  const void* beg,
  const void* end,
  uint32_t radius)
{
  return new RadiusLookupStrategy<HashLength>(
    beg, end,
    radius == std::numeric_limits<uint32_t>::max() ?
      compute_radius<HashLength>(
        static_cast<const std::array<uint8_t, HashLength>*>(beg),
        static_cast<const std::array<uint8_t, HashLength>*>(end)) :
      radius
  );
}
