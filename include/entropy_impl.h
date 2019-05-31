#pragma once

#include <cstdint>
#include <memory>

#include "hasher_impl.h"

class EntropyCalculator: public HasherImpl {
public:
  virtual ~EntropyCalculator() {}

  virtual void update(const uint8_t* beg, const uint8_t* end);

  virtual void set_total_input_length(uint64_t) {}

  virtual void get(void* val);

  double entropy() const;

  virtual void reset();

  virtual EntropyCalculator* clone() const;

private:
  uint64_t Hist[256] = {0};
};

std::unique_ptr<HasherImpl> make_entropy_calculator();
