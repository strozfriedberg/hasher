#pragma once

#include "lookupstrategy.h"

#include <algorithm>
#include <array>
#include <memory>

template <size_t HashLength>
std::array<uint8_t, HashLength>* hash_ptr_cast(const void* ptr) {
  return static_cast<std::array<uint8_t, HashLength>*>(const_cast<void*>(ptr));
}

template <size_t HashLength>
class BasicLookupStrategy: public LookupStrategy {
public:
  BasicLookupStrategy(const void* beg, const void* end):
    HashesBeg(nullptr, nullptr)
  {
    auto b = hash_ptr_cast<HashLength>(beg);
    auto e = hash_ptr_cast<HashLength>(end);

    HashesBeg = {b, [](std::array<uint8_t, HashLength>*){}};
    HashesEnd = e;
  }

  virtual ~BasicLookupStrategy() {}

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
  std::unique_ptr<
    std::array<uint8_t, HashLength>[],
    void(*)(std::array<uint8_t, HashLength>*)
  > HashesBeg;

  std::array<uint8_t, HashLength>* HashesEnd;
};
