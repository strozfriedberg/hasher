#pragma once

#include "hasher/api.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <numeric>
#include <string>

class SFHASH_HashSet {
public:
  virtual ~SFHASH_HashSet() {}

  virtual bool contains(const uint8_t* hash) const = 0;
};

template <size_t HashLength>
std::array<uint8_t, HashLength>* hash_ptr_cast(const void* ptr) {
  return static_cast<std::array<uint8_t, HashLength>*>(const_cast<void*>(ptr));
}

template <size_t HashLength>
class HashSetImpl: public SFHASH_HashSet {
public:
  HashSetImpl(const void* beg, const void* end, bool shared):
    HashesBeg(nullptr, nullptr)
  {
    auto b = hash_ptr_cast<HashLength>(beg);
    auto e = hash_ptr_cast<HashLength>(end);

    if (shared) {
      HashesBeg = {b, [](std::array<uint8_t, HashLength>*){}};
      HashesEnd = e;
    }
    else {
      const size_t count = e - b;
      HashesBeg = {
        new std::array<uint8_t, HashLength>[count],
        [](std::array<uint8_t, HashLength>* h){ delete[] h; }
      };
      HashesEnd = HashesBeg.get() + count;
      std::memcpy(HashesBeg.get(), b, count * HashLength);
    }
  }

  virtual ~HashSetImpl() {}

  virtual bool contains(const uint8_t* hash) const {
    return std::binary_search(
      HashesBeg.get(), HashesEnd,
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }

protected:
  std::unique_ptr<std::array<uint8_t, HashLength>[], void(*)(std::array<uint8_t, HashLength>*)> HashesBeg;
  std::array<uint8_t, HashLength>* HashesEnd;
};

uint32_t expected_index(const uint8_t* h, uint32_t set_size);

template <size_t HashLength>
uint32_t compute_radius(
  const std::array<uint8_t, HashLength>* beg,
  const std::array<uint8_t, HashLength>* end
)
{
// FIXME: types
  const uint32_t count = end - beg;
  int64_t max_delta = 0;
  for (ssize_t i = 0; i < count; ++i) {
    max_delta = std::max(max_delta,
                         std::abs(i - expected_index(beg[i].data(), count)));
  }
  return max_delta;
}

template <size_t HashLength>
class HashSetRadiusImpl: public HashSetImpl<HashLength> {
public:
  HashSetRadiusImpl(
    const void* beg,
    const void* end,
    bool shared,
    uint32_t radius
  ):
    HashSetImpl<HashLength>(beg, end, shared), Radius(radius) {}

  virtual ~HashSetRadiusImpl() {}

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
