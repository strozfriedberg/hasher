
#pragma once

#include "hasher_impl.h"

#include <fuzzy.h>

class FuzzyHasher: public HasherImpl {
public:
  // TODO: set_total_input_length
  virtual ~FuzzyHasher() {
    fuzzy_free(ctx);
  }

  FuzzyHasher():
    ctx(fuzzy_new())
  {}

  FuzzyHasher(const FuzzyHasher& other):
    ctx(fuzzy_clone(other.ctx))
  {}

  FuzzyHasher(FuzzyHasher&&) = default;

  FuzzyHasher& operator=(FuzzyHasher&&) = default;

  virtual void update(const uint8_t* beg, const uint8_t* end) {
    if (!fuzzy_update(ctx, beg, end-beg)) {
      // TODO: error!
    }
  }

  virtual void get(void* val) {
    if (!fuzzy_digest(ctx, reinterpret_cast<char*>(val), 0)) {
      // TODO: error!
    }
  }

  virtual void reset() {
    fuzzy_free(ctx);
    ctx = fuzzy_new();
  }

  virtual FuzzyHasher* clone() const {
    return new FuzzyHasher(*this);
  }

private:
  struct fuzzy_state* ctx;
};

inline std::unique_ptr<HasherImpl> make_fuzzy_hasher() {
  return std::unique_ptr<FuzzyHasher>(new FuzzyHasher());
}
