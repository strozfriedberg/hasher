#include <memory>

#include "fuzzy_hasher.h"
#include "util.h"

#include <fuzzy.h>

FuzzyHasher::FuzzyHasher() :
  ctx(make_unique_del(fuzzy_new(), fuzzy_free))
{}

FuzzyHasher::FuzzyHasher(const FuzzyHasher& other) :
  ctx(make_unique_del(fuzzy_clone(other.ctx.get()), fuzzy_free))
{}

void FuzzyHasher::update(const uint8_t* beg, const uint8_t* end) {
  if (!fuzzy_update(ctx.get(), beg, end-beg)) {
    // TODO: error!
  }
}

void FuzzyHasher::set_total_input_length(uint64_t len) {
  if (!fuzzy_set_total_input_length(ctx.get(), len)) {
    // TODO: error!
  }
}

void FuzzyHasher::get(void* val) {
  if (!fuzzy_digest(ctx.get(), static_cast<char*>(val), 0)) {
    // TODO: error!
  }
}
void FuzzyHasher::reset() {
  ctx.reset(fuzzy_new());
}

FuzzyHasher* FuzzyHasher::clone() const {
  return new FuzzyHasher(*this);
}

std::unique_ptr<HasherImpl> make_fuzzy_hasher() {
  return std::unique_ptr<FuzzyHasher>(new FuzzyHasher());
}
