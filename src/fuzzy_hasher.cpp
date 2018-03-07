#include <memory>

#include "fuzzy_hasher.h"

#include <fuzzy.h>

FuzzyHasher::~FuzzyHasher() {
  fuzzy_free(ctx);
}

FuzzyHasher::FuzzyHasher() :
  ctx(fuzzy_new())
{}

FuzzyHasher::FuzzyHasher(const FuzzyHasher& other) :
  ctx(fuzzy_clone(other.ctx))
{}

void FuzzyHasher::update(const uint8_t* beg, const uint8_t* end) {
  if (!fuzzy_update(ctx, beg, end-beg)) {
    // TODO: error!
  }
}

void FuzzyHasher::set_total_input_length(uint64_t len) {
  if (!fuzzy_set_total_input_length(ctx, len)) {
    // TODO: error!
  }
}

void FuzzyHasher::get(void* val) {
  if (!fuzzy_digest(ctx, static_cast<char*>(val), 0)) {
    // TODO: error!
  }
}
void FuzzyHasher::reset() {
  fuzzy_free(ctx);
  ctx = fuzzy_new();
}

FuzzyHasher* FuzzyHasher::clone() const {
  return new FuzzyHasher(*this);
}

std::unique_ptr<HasherImpl> make_fuzzy_hasher() {
  return std::unique_ptr<FuzzyHasher>(new FuzzyHasher());
}
