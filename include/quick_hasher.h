#pragma once

#include "libcrypto_hasher.h"

static const uint32_t MAX_QUICK_HASH_BYTES = 256;

class QuickHasher: public LibcryptoHasher {
public:
  QuickHasher(const EVP_MD* hfunc);
  QuickHasher(const QuickHasher& other);
  QuickHasher& operator=(const QuickHasher& other);

  virtual void update(const uint8_t* beg, const uint8_t* end) override;
  virtual void reset() override;

private:
  uint64_t Offset = 0;
};

std::unique_ptr<HasherImpl> make_quick_md5_hasher();
