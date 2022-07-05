#include "catch.hpp"

#include "hasher/api.h"
#include "util.h"

#include <algorithm>
#include <numeric>

TEST_CASE("entropyNoUpdate") {
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_ENTROPY), sfhash_destroy_hasher
  );

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  REQUIRE(0.0 == hashes.Entropy);
}

TEST_CASE("entropyEmptyUpdate") {
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_ENTROPY), sfhash_destroy_hasher
  );

  sfhash_update_hasher(hasher.get(), nullptr, nullptr);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  REQUIRE(0.0 == hashes.Entropy);
}

TEST_CASE("entropyAll00") {
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_ENTROPY), sfhash_destroy_hasher
  );

  const uint8_t buf[1024] = {0};

  sfhash_update_hasher(hasher.get(), std::begin(buf), std::end(buf));

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  REQUIRE(0.0 == hashes.Entropy);
}

TEST_CASE("entropyAllFF") {
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_ENTROPY), sfhash_destroy_hasher
  );

  uint8_t buf[1024];
  std::fill(std::begin(buf), std::end(buf), 0xFF);

  sfhash_update_hasher(hasher.get(), std::begin(buf), std::end(buf));

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  REQUIRE(0.0 == hashes.Entropy);
}

TEST_CASE("entropyEqual") {
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_ENTROPY), sfhash_destroy_hasher
  );

  uint8_t buf[1024];
  for (uint32_t i = 0; i < sizeof(buf); ++i) {
    buf[i] = i & 0xFF;
  }

  sfhash_update_hasher(hasher.get(), std::begin(buf), std::end(buf));

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  REQUIRE(8.0 == hashes.Entropy);
}
