#include "quick_hasher.h"

QuickHasher::QuickHasher(const QuickHasher& other):
  LibcryptoHasher(other),
  Offset(other.Offset)
{}

QuickHasher& QuickHasher::operator=(const QuickHasher& other) {
  LibcryptoHasher::operator=(other);

  Offset = other.Offset;
  return *this;
}

void QuickHasher::update(const uint8_t* beg, const uint8_t* end) {
  if (Offset < MAX_QUICK_HASH_BYTES) {
    LibcryptoHasher::update(beg,
                            beg
                              + std::min(static_cast<decltype(end - beg)>(MAX_QUICK_HASH_BYTES),
                                         end - beg));
  }
}

std::unique_ptr<HasherImpl> make_quick_md5_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_md5()));
}
