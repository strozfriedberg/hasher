#pragma once

#include "hashset/basic_ls.h"
#include "hashset/util.h"

#include <algorithm>
#include <array>

template <
  size_t HashLength,
  size_t BlockBits
>
class BlockLinearLookupStrategy: public BasicLookupStrategy<HashLength> {
public:
  BlockLinearLookupStrategy(
    const void* beg,
    const void* end,
//    std::array<std::tuple<double, double, double, double>, (1 << BlockBits)> blocks
    std::array<std::tuple<float, float, float, float>, (1 << BlockBits)> blocks
  ):
    BasicLookupStrategy<HashLength>(beg, end),
    Blocks(blocks)
  {}

  virtual ~BlockLinearLookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const override {
    const size_t exp = expected_index(hash, this->HashesEnd - this->HashesBeg.get());

    const size_t bi = hash[0] >> (8 - BlockBits);
/*
    std::cout << bi << '\n';

    std::cout << (exp + static_cast<size_t>(std::get<0>(Blocks[bi])*exp + std::get<1>(Blocks[bi]))) << ", " << (exp + static_cast<size_t>(std::get<2>(Blocks[bi])*exp + std::get<3>(Blocks[bi])) + 1) << '\n';

    std::cout << to_hex(*std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp + static_cast<size_t>(std::get<0>(Blocks[bi])*exp + std::get<1>(Blocks[bi])))) << '\n' << to_hex(*std::min(this->HashesEnd, this->HashesBeg.get() + exp + static_cast<size_t>(std::get<2>(Blocks[bi])*exp + std::get<3>(Blocks[bi])) + 1)) << '\n';
*/

    return std::binary_search(
      std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp + static_cast<int64_t>(std::get<0>(Blocks[bi])*exp + std::get<1>(Blocks[bi]))),
      std::min(this->HashesEnd, this->HashesBeg.get() + exp + static_cast<int64_t>(std::get<2>(Blocks[bi])*exp + std::get<3>(Blocks[bi])) + 1),
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }

//protected:
//  std::array<std::tuple<double, double, double, double>, (1 << BlockBits)> Blocks;
  std::array<std::tuple<float, float, float, float>, (1 << BlockBits)> Blocks;
};
