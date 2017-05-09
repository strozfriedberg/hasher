#include "hasher.h"

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>

using HashAlgorithms = SFHASH_HashAlgorithms;
using HashValues = SFHASH_HashValues;

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

class SFHASH_Hasher {
public:
  SFHASH_Hasher(uint32_t algs) {
    const std::pair<const EVP_MD* (*)(void), off_t> init[] {
      { EVP_md5,    offsetof(SFHASH_HashValues, md5)    },
      { EVP_sha1,   offsetof(HashValues, sha1)   },
      { EVP_sha256, offsetof(HashValues, sha256) }
    };

    for (uint32_t i = 0; i < sizeof(init) && algs; algs >>= 1, ++i) {
      if (algs & 1) {
        hashers.emplace_back(LibcryptoHasher(init[i].first()), init[i].second);
      }
    }
  }

  SFHASH_Hasher(const SFHASH_Hasher&) = default;

  SFHASH_Hasher(SFHASH_Hasher&& other) = default;

  SFHASH_Hasher& operator=(const SFHASH_Hasher&) = default;

  SFHASH_Hasher& operator=(SFHASH_Hasher&&) = default;

  void update(const uint8_t* beg, const uint8_t* end) {
    for (auto& h: hashers) {
      h.first.update(beg, end);
    }
  }

  void get(HashValues* vals) {
    for (auto& h: hashers) {
      h.first.get(reinterpret_cast<uint8_t*>(vals) + h.second);
    }
  }

  void reset() {
    for (auto& h: hashers) {
      h.first.reset();
    }
  }

private:
  std::vector<std::pair<LibcryptoHasher, off_t>> hashers;
};

using Hasher = SFHASH_Hasher;

Hasher* sfhash_create_hasher(uint32_t hashAlgs) {
  return new Hasher(hashAlgs);
}

Hasher* sfhash_clone_hasher(const Hasher* hasher) {
  return new Hasher(*hasher);
}

void sfhash_update_hasher(Hasher* hasher, const void* beg, const void* end) {
  hasher->update(static_cast<const uint8_t*>(beg),
                 static_cast<const uint8_t*>(end));
}

void sfhash_get_hashes(Hasher* hasher, HashValues* hashes) {
  hasher->get(hashes);
}

void sfhash_reset_hasher(Hasher* hasher) {
  hasher->reset();
}

void sfhash_destroy_hasher(Hasher* hasher) {
  delete hasher;
}
