#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <memory>
#include <numeric>

#include "hasher_impl.h"

class SFHASH_Entropy: public HasherImpl {
public:
  virtual ~SFHASH_Entropy() {}

  virtual void update(const uint8_t* beg, const uint8_t* end);

  virtual void set_total_input_length(uint64_t) {}

  virtual void get(void* val);

  double entropy() const;

  virtual void reset();

  virtual SFHASH_Entropy* clone() const;

private:
  uint64_t Hist[256] = {0};
  friend void sfhash_accumulate_entropy(SFHASH_Entropy* sum, const SFHASH_Entropy* addend);
};

std::unique_ptr<HasherImpl> make_entropy_calculator();
