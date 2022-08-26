#pragma once

#include "hsd_impls/basic_hsd.h"
#include "hsd_impls/hsd_utils.h"

#include <algorithm>
#include <array>

template <size_t HashLength>
class RangeHashSetDataImpl: public BasicHashSetDataImpl<HashLength> {
public:
  RangeHashSetDataImpl(
    const void* beg,
    const void* end,
    int64_t left,
    int64_t right
  ):
    BasicHashSetDataImpl<HashLength>(beg, end),
    Left(left),
    Right(right)
  {
  }

  virtual ~RangeHashSetDataImpl() {}

  virtual bool contains(const uint8_t* hash) const override {
    const size_t exp = expected_index(hash, this->HashesEnd - this->HashesBeg.get());

/*
    {
      const auto l = std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp + RadiusLeft);
      const auto r = std::min(this->HashesEnd, this->HashesBeg.get() + exp + RadiusRight + 1);
      const auto i = std::lower_bound(
        this->HashesBeg.get(),
        this->HashesEnd,
        *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
      );

      if (i < l || i >= r) {
        std::cout << "!\n";
      }
    }
*/

    return std::binary_search(
      std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp + Left),
      std::min(this->HashesEnd, this->HashesBeg.get() + exp + Right + 1),
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }

protected:
  int64_t Left, Right;
};

