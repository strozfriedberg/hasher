#pragma once

#include "hasher_impl.h"

#include <fuzzy.h>

class FuzzyHasher: public HasherImpl {
public:
  virtual ~FuzzyHasher();

  FuzzyHasher();

  FuzzyHasher(const FuzzyHasher& other);

  FuzzyHasher(FuzzyHasher&&) = default;

  FuzzyHasher& operator=(FuzzyHasher&&) = default;

  virtual void update(const uint8_t* beg, const uint8_t* end);

  virtual void set_total_input_length(uint64_t len);

  virtual void get(void* val);

  virtual void reset();

  virtual FuzzyHasher* clone() const;

private:
  fuzzy_state* ctx;
};

std::unique_ptr<HasherImpl> make_fuzzy_hasher();
