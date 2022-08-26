#pragma once

#include "hsd_impls/basic_hsd.h"

template <
  size_t HashLength,
  size_t BlockBits
>
class BlockHashSetDataImpl: public BasicHashSetDataImpl<HashLength> {
public:
  BlockHashSetDataImpl(
    const void* beg,
    const void* end,
    std::array<std::pair<ssize_t, ssize_t>, (1 << BlockBits)> blocks
  ):
    BasicHashSetDataImpl<HashLength>(beg, end),
    Blocks(blocks)
  {}

  virtual ~BlockHashSetDataImpl() {}

  virtual bool contains(const uint8_t* hash) const override {
    const size_t exp = expected_index(hash, this->HashesEnd - this->HashesBeg.get());
    const size_t bi = hash[0] >> (8 - BlockBits);

/*
    {
      const auto l = std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp + Blocks[bi].first);
      const auto r = std::min(this->HashesEnd, this->HashesBeg.get() + exp + Blocks[bi].second + 1);
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
      std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp + Blocks[bi].first),
      std::min(this->HashesEnd, this->HashesBeg.get() + exp + Blocks[bi].second + 1),
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }

protected:
  std::array<std::pair<ssize_t, ssize_t>, (1 << BlockBits)> Blocks;
};
