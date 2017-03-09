#include "hasher.h"

#include <iostream>
#include <string>
#include <vector>

#include <botan/ffi.h>

using HashAlgorithms = SFHASH_HashAlgorithms;
using HashValues = SFHASH_HashValues;

class BotanHasher {
public:
  BotanHasher(const char* name) {
    botan_hash_init(&hasher, name, 0);
  }

  BotanHasher(const BotanHasher&) = delete;

  BotanHasher(BotanHasher&& other): hasher(other.hasher) {
    other.hasher = nullptr;
  }

  BotanHasher& operator=(const BotanHasher&) = delete;

  BotanHasher& operator=(BotanHasher&& other) {
    hasher = other.hasher;
    return *this;
  }

  ~BotanHasher() {
    botan_hash_destroy(hasher);
  }

  void update(const uint8_t* beg, const uint8_t* end) {
    botan_hash_update(hasher, beg, end - beg);
  }

  void get(uint8_t* val) {
    botan_hash_final(hasher, val);
  }

  void reset() {
    botan_hash_clear(hasher);
  }

private:
  botan_hash_t hasher;
};

class SFHASH_Hasher {
public:
  SFHASH_Hasher(uint32_t algs) {
    const std::pair<const char*, off_t> init[] {
      { "MD5",    offsetof(HashValues, md5)    },
      { "SHA1",   offsetof(HashValues, sha1)   },
      { "SHA-256", offsetof(HashValues, sha256) }
    };

    for (uint32_t i = 0; i < sizeof(init) && algs; algs >>= 1, ++i) {
      if (algs & 1) {
        hashers.emplace_back(BotanHasher(init[i].first), init[i].second);
      }
    }
  }

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
  std::vector<std::pair<BotanHasher, off_t>> hashers;
};

using Hasher = SFHASH_Hasher;

Hasher* sfhash_create_hasher(uint32_t hashAlgs) {
  return new Hasher(hashAlgs);
}

/*
Hasher* sfhash_clone_hasher(const Hasher* hasher) {
}
*/

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
