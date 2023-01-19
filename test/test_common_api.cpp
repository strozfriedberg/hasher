#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <tuple>
#include <vector>

#include "hasher/common.h"

TEST_CASE("hash_type_metadata") {
  const std::vector<std::tuple<SFHASH_HashAlgorithm, const char*, size_t>> tests{
    { SFHASH_INVALID, nullptr, 0 },
    { SFHASH_MD5, "MD5", 16 },
    { SFHASH_SHA_1, "SHA-1", 20 },
    { SFHASH_SHA_2_224, "SHA-2-224", 28 },
    { SFHASH_SHA_2_256, "SHA-2-256", 32 },
    { SFHASH_SHA_2_384, "SHA-2-384", 48 },
    { SFHASH_SHA_2_512, "SHA-2-512", 64 },
    { SFHASH_SHA_3_224, "SHA-3-224", 28 },
    { SFHASH_SHA_3_256, "SHA-3-256", 32 },
    { SFHASH_SHA_3_384, "SHA-3-384", 48 },
    { SFHASH_SHA_3_512, "SHA-3-512", 64 },
    { SFHASH_BLAKE3, "BLAKE3", 32 },
    { SFHASH_FUZZY, "Fuzzy", 148 },
    { SFHASH_ENTROPY, "Entropy", 8 },
    { SFHASH_SIZE, "Size", 8 },
    { SFHASH_QUICK_MD5, "Quick MD5", 16 }
  };

  for (const auto& [e_alg, e_name, e_len]: tests) {
    DYNAMIC_SECTION("alg " << e_alg << " => name " << e_name) {
      const auto a_name = sfhash_hash_name(e_alg);
      if (!e_name) {
        CHECK(!a_name);
      }
      else {
        CHECK(!std::strcmp(e_name, a_name));
      }
    }

    DYNAMIC_SECTION("name " << e_name << " => alg " << e_alg) {
      CHECK(sfhash_hash_type(e_name) == e_alg);
    }

    DYNAMIC_SECTION(e_name << " length") {
      CHECK(sfhash_hash_length(e_alg) == e_len);
    }
  }
}
