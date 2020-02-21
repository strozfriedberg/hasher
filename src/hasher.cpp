#include <cstddef>
#include <vector>

#include "hasher/api.h"

#include "entropy_impl.h"
#include "fuzzy_hasher.h"
#include "hasher_impl.h"
#include "libcrypto_hasher.h"
#include "quick_hasher.h"

using HashValues = SFHASH_HashValues;

// TODO: make a header for this class once hasher.h is empty
class SFHASH_Hasher {
public:
  SFHASH_Hasher(uint32_t algs) {
    const std::vector<std::pair<std::unique_ptr<HasherImpl> (*)(void), off_t>>
      init{{make_md5_hasher,         offsetof(HashValues, Md5)     },
           {make_sha1_hasher,        offsetof(HashValues, Sha1)    },
           {make_sha2_224_hasher,    offsetof(HashValues, Sha2_224)},
           {make_sha2_256_hasher,    offsetof(HashValues, Sha2_256)},
           {make_sha2_384_hasher,    offsetof(HashValues, Sha2_384)},
           {make_sha2_512_hasher,    offsetof(HashValues, Sha2_512)},
           {make_sha3_224_hasher,    offsetof(HashValues, Sha3_224)},
           {make_sha3_256_hasher,    offsetof(HashValues, Sha3_256)},
           {make_sha3_384_hasher,    offsetof(HashValues, Sha3_384)},
           {make_sha3_512_hasher,    offsetof(HashValues, Sha3_512)},
           {make_fuzzy_hasher,       offsetof(HashValues, Fuzzy)   },
           {make_entropy_calculator, offsetof(HashValues, Entropy) },
           {make_quick_md5_hasher,   offsetof(HashValues, QuickMd5)}};

    for (uint32_t i = 0; i < init.size() && algs; algs >>= 1, ++i) {
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

  void set_total_input_length(uint64_t len) {
    for (auto& h: hashers) {
      h.first->set_total_input_length(len);
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
      hashers.emplace_back(std::unique_ptr<HasherImpl>(h.first->clone()), h.second);
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
  hasher->update(static_cast<const uint8_t*>(beg), static_cast<const uint8_t*>(end));
}

void sfhash_hasher_set_total_input_length(Hasher* hasher, uint64_t total_fixed_length) {
  hasher->set_total_input_length(total_fixed_length);
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
