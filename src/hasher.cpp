#include "hasher.h"

#include <string>
#include <vector>

//#include <botan/ffi.h>

using HashAlgorithms = SFHASH_HashAlgorithms;
using HashValues = SFHASH_HashValues;

/*
class BotanHasher {
public:
  BotanHasher(const char* name) {
    botan_hash_init(&hasher, name, 0);
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
*/

/*
class SFHASH_Hasher {
public:
  SFHASH_Hasher(uint32_t algs) {
    const std::pair<std::string, uint8_t* HashValues::*> init[] {
      std::make_pair("MD5", &HashValues::md5),
      { "SHA1",   &HashValues::sha1   },
      { "SHA256", &HashValues::sha256 }
    };

    for (int i = 0; i < 3 && algs; algs >>= 1, ++i) {
      if (algs & 1) {
        hashers.emplace_back(init[i].first, init[i].second);
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
      h.first.get(vals->*(h.second));
    }
  }

  void reset() {
    for (auto& h: hashers) {
      h.first.reset();
    }
  } 

private:
  std::vector<std::pair<BotanHasher, uint8_t* HashValues::*>> hashers;
};
*/

using Hasher = SFHASH_Hasher;

Hasher* sfhash_create_hasher(uint32_t hashAlgs) {
//  return new Hasher(hashAlgs);
  return reinterpret_cast<Hasher*>(0xDEADBEEF);
}

/*
Hasher* sfhash_clone_hasher(const Hasher* hasher) {
}
*/

void sfhash_update_hasher(Hasher* hasher, const void* beg, const void* end) {
/*
  hasher->update(static_cast<const uint8_t*>(beg),
                 static_cast<const uint8_t*>(end));
*/
}

void sfhash_get_hashes(Hasher* hasher, HashValues* hashes) {
//  hasher->get(hashes);
}

void sfhash_reset_hasher(Hasher* hasher) {
//  hasher->reset();
}

void sfhash_destroy_hasher(Hasher* hasher) {
//  delete hasher;
}
