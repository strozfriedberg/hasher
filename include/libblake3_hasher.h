#pragma once

#include "hasher_impl.h"

#include <memory>

#include <blake3.h>

class Libblake3Hasher: public HasherImpl {
public:
  Libblake3Hasher();

  Libblake3Hasher(const Libblake3Hasher& other) = default;

  Libblake3Hasher(Libblake3Hasher&&) = default;

  Libblake3Hasher& operator=(const Libblake3Hasher& other) = default;

  Libblake3Hasher& operator=(Libblake3Hasher&&) = default;

  virtual ~Libblake3Hasher() {}

  virtual Libblake3Hasher* clone() const;

  virtual void update(const uint8_t* beg, const uint8_t* end);

  virtual void set_total_input_length(uint64_t) {}

  virtual void get(void* val);

  virtual void reset();

private:
  blake3_hasher Hasher;
};

std::unique_ptr<HasherImpl> make_blake3_hasher();
