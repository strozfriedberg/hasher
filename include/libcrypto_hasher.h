#pragma once

#include "hasher_impl.h"

#include <memory>

#include <openssl/evp.h>

class LibcryptoHasher: public HasherImpl {
public:
  LibcryptoHasher(const EVP_MD* hfunc):
    ctx(EVP_MD_CTX_create()), hfunc(hfunc)
  {
    reset();
  }

  LibcryptoHasher(const LibcryptoHasher& other):
    ctx(EVP_MD_CTX_create()), hfunc(other.hfunc)
  {
    if (!EVP_MD_CTX_copy(ctx, other.ctx)) {
      // TODO: error!
    }
  }

  LibcryptoHasher(LibcryptoHasher&&) = default;

  LibcryptoHasher& operator=(const LibcryptoHasher& other) {
    if (!EVP_MD_CTX_copy(ctx, other.ctx)) {
      // TODO: error!
    }

    hfunc = other.hfunc;
    return *this;
  }

  LibcryptoHasher& operator=(LibcryptoHasher&&) = default;

  virtual ~LibcryptoHasher() {
    EVP_MD_CTX_destroy(ctx);
  }

  virtual LibcryptoHasher* clone() const {
    return new LibcryptoHasher(*this);
  }

  virtual void update(const uint8_t* beg, const uint8_t* end) {
    if (!EVP_DigestUpdate(ctx, beg, end - beg)) {
      // TODO: error!
    }
  }

  virtual void get(void* val) {
    if (!EVP_DigestFinal_ex(ctx, static_cast<uint8_t*>(val), nullptr)) {
      // TODO: error!
    }
  }

  virtual void reset() {
    if (!EVP_DigestInit(ctx, hfunc)) {
      // TODO: error!
    }
  }

private:
  EVP_MD_CTX* ctx;
  const EVP_MD* hfunc;
};

inline std::unique_ptr<HasherImpl> make_md5_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_md5()));
}

inline std::unique_ptr<HasherImpl> make_sha1_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha1()));
}

inline std::unique_ptr<HasherImpl> make_sha256_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha256()));
}
