#pragma once

#include "hasher/api.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <numeric>
#include <string>

class SFHASH_HashSetData {
public:
  virtual ~SFHASH_HashSetData() {}

  virtual bool contains(const uint8_t* hash) const = 0;

  virtual const uint8_t* data() const = 0;
};

template <size_t HashLength>
std::array<uint8_t, HashLength>* hash_ptr_cast(const void* ptr) {
  return static_cast<std::array<uint8_t, HashLength>*>(const_cast<void*>(ptr));
}

template <size_t HashLength>
class HashSetDataImpl: public SFHASH_HashSetData {
public:
  HashSetDataImpl(const void* beg, const void* end):
    HashesBeg(nullptr, nullptr)
  {
    auto b = hash_ptr_cast<HashLength>(beg);
    auto e = hash_ptr_cast<HashLength>(end);

    HashesBeg = {b, [](std::array<uint8_t, HashLength>*){}};
    HashesEnd = e;
  }

  virtual ~HashSetDataImpl() {}

  virtual bool contains(const uint8_t* hash) const {
    return std::binary_search(
      HashesBeg.get(), HashesEnd,
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }

  virtual const uint8_t* data() const {
    return reinterpret_cast<const uint8_t*>(HashesBeg.get());
  }

protected:
  std::unique_ptr<std::array<uint8_t, HashLength>[], void(*)(std::array<uint8_t, HashLength>*)> HashesBeg;
  std::array<uint8_t, HashLength>* HashesEnd;
};

uint32_t expected_index(const uint8_t* h, uint32_t set_size);

template <size_t HashLength>
class HashSetDataRadiusImpl: public HashSetDataImpl<HashLength> {
public:
  HashSetDataRadiusImpl(
    const void* beg,
    const void* end,
    uint32_t radius
  ):
    HashSetDataImpl<HashLength>(beg, end), Radius(radius) {}

  virtual ~HashSetDataRadiusImpl() {}

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
SFHASH_HashSetData* make_hashset_data(
  const void* beg,
  const void* end,
  uint32_t radius)
{
  return new HashSetDataRadiusImpl<HashLength>(
    beg, end,
    radius == std::numeric_limits<uint32_t>::max() ?
      compute_radius<HashLength>(
        static_cast<const std::array<uint8_t, HashLength>*>(beg),
        static_cast<const std::array<uint8_t, HashLength>*>(end)) :
      radius
  );
}

SFHASH_HashSetData* load_hashset_data(
  const SFHASH_HashSetInfo* hsinfo,
  const void* beg,
  const void* end
);
