#pragma once

#include <openssl/evp.h>

class LibcryptoHasher {
public:
  LibcryptoHasher(const EVP_MD* hfunc):
    ctx(EVP_MD_CTX_create()), hfunc(hfunc), hlen(EVP_MD_size(hfunc))
  {
    reset();
  }

  LibcryptoHasher(const LibcryptoHasher& other):
    ctx(EVP_MD_CTX_create()), hfunc(other.hfunc), hlen(other.hlen)
  {
    if (!EVP_MD_CTX_copy(ctx, other.ctx)) {
      // error!
    }
  }

  LibcryptoHasher(LibcryptoHasher&& other):
    ctx(other.ctx), hfunc(other.hfunc), hlen(other.hlen)
  {
    other.ctx = nullptr;
  }

  LibcryptoHasher& operator=(const LibcryptoHasher& other) {
    if (!EVP_MD_CTX_copy(ctx, other.ctx)) {
      // error!
    }

    hfunc = other.hfunc;
    hlen = other.hlen;
    return *this;
  }

  LibcryptoHasher& operator=(LibcryptoHasher&& other) {
    ctx = other.ctx;
    other.ctx = nullptr;
    hfunc = other.hfunc;
    hlen = other.hlen;
    return *this;
  }

  ~LibcryptoHasher() {
    EVP_MD_CTX_destroy(ctx);
  }

  void update(const uint8_t* beg, const uint8_t* end) {
    if (!EVP_DigestUpdate(ctx, beg, end - beg)) {
      // error!
    }
  }

  void get(uint8_t* val) {
    if (!EVP_DigestFinal_ex(ctx, val, nullptr)) {
      // error!
    }
  }

  void reset() {
    if (!EVP_DigestInit(ctx, hfunc)) {
      // error!
    }
  }

private:
  EVP_MD_CTX* ctx;
  const EVP_MD* hfunc;
  uint32_t hlen;
};

inline LibcryptoHasher make_md5_hasher() {
  return LibcryptoHasher(EVP_md5());
}

inline LibcryptoHasher make_sha1_hasher() {
  return LibcryptoHasher(EVP_sha1());
}

inline LibcryptoHasher make_sha256_hasher() {
  return LibcryptoHasher(EVP_sha256());
}
