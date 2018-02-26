#include "hasher.h"

#include "hasher_impl.h"
#include "entropy_impl.h"
#include "libcrypto_hasher.h"

#include <cstddef>
#include <vector>

#include <openssl/evp.h>

using HashValues = SFHASH_HashValues;

class SFHASH_Hasher {
public:
  SFHASH_Hasher(uint32_t algs) {
    const std::pair<std::unique_ptr<HasherImpl> (*)(void), off_t> init[] {
      { make_md5_hasher,         offsetof(HashValues, md5)     },
      { make_sha1_hasher,        offsetof(HashValues, sha1)    },
      { make_sha256_hasher,      offsetof(HashValues, sha256)  },
      { make_entropy_calculator, offsetof(HashValues, entropy) }
    };

    for (uint32_t i = 0; i < sizeof(init) && algs; algs >>= 1, ++i) {
      if (algs & 1) {
        hashers.emplace_back(init[i].first(), init[i].second);
      }
    }
  }

  SFHASH_Hasher(const SFHASH_Hasher& other) {
    copy_members(other);
  }

  SFHASH_Hasher(SFHASH_Hasher&&) = default;

  SFHASH_Hasher& operator=(const SFHASH_Hasher& other) {
    hashers.clear();
    copy_members(other);
    return *this;
  }

  SFHASH_Hasher& operator=(SFHASH_Hasher&&) = default;

  void update(const uint8_t* beg, const uint8_t* end) {
    for (auto& h: hashers) {
      h.first->update(beg, end);
    }
  }

  void get(HashValues* vals) {
    for (auto& h: hashers) {
      h.first->get(reinterpret_cast<uint8_t*>(vals) + h.second);
    }
  }

  void reset() {
    for (auto& h: hashers) {
      h.first->reset();
    }
  }

private:
  void copy_members(const SFHASH_Hasher& other) {
    for (const auto& h: other.hashers) {
      hashers.emplace_back(
        std::unique_ptr<HasherImpl>(h.first->clone()),
        h.second
      );
    }
  }

  std::vector<std::pair<std::unique_ptr<HasherImpl>, off_t>> hashers;
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
