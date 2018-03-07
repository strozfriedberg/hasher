#pragma once

#include "hasher_impl.h"

#include <memory>

#include <openssl/evp.h>

class LibcryptoHasher: public HasherImpl {
public:
  LibcryptoHasher(const EVP_MD* hfunc);

  LibcryptoHasher(const LibcryptoHasher& other);

  LibcryptoHasher(LibcryptoHasher&&) = default;

  LibcryptoHasher& operator=(const LibcryptoHasher& other);

  LibcryptoHasher& operator=(LibcryptoHasher&&) = default;

  virtual ~LibcryptoHasher();

  virtual LibcryptoHasher* clone() const;

  virtual void update(const uint8_t* beg, const uint8_t* end);

  virtual void set_total_input_length(uint64_t) {}

  virtual void get(void* val);

  virtual void reset();

private:
  EVP_MD_CTX* ctx;
  const EVP_MD* hfunc;
};

std::unique_ptr<HasherImpl> make_md5_hasher();

std::unique_ptr<HasherImpl> make_sha1_hasher();

std::unique_ptr<HasherImpl> make_sha256_hasher();
