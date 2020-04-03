#include "libblake3_hasher.h"

Libblake3Hasher::Libblake3Hasher()
{
  reset();
}

Libblake3Hasher* Libblake3Hasher::clone() const {
  return new Libblake3Hasher(*this);
}

void Libblake3Hasher::update(const uint8_t* beg, const uint8_t* end) {
  blake3_hasher_update(&Hasher, beg, end - beg);
}

void Libblake3Hasher::get(void* val) {
  blake3_hasher_finalize(&Hasher, static_cast<uint8_t*>(val), BLAKE3_OUT_LEN);
}

void Libblake3Hasher::reset() {
  blake3_hasher_init(&Hasher);
}

std::unique_ptr<HasherImpl> make_blake3_hasher() {
  return std::unique_ptr<Libblake3Hasher>(new Libblake3Hasher());
}
