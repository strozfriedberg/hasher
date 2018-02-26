#include <scope/test.h>

#include "hasher.h"
#include "util.h"

#include <algorithm>
#include <numeric>


SCOPE_TEST(entropyNoUpdate) {
  auto hasher = make_unique_del(
    sfhash_create_hasher(ENTROPY),
    sfhash_destroy_hasher
  );

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  SCOPE_ASSERT_EQUAL(0.0, hashes.entropy);
}

SCOPE_TEST(entropyEmptyUpdate) {
  auto hasher = make_unique_del(
    sfhash_create_hasher(ENTROPY),
    sfhash_destroy_hasher
  );

  sfhash_update_hasher(hasher.get(), nullptr, nullptr);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  SCOPE_ASSERT_EQUAL(0.0, hashes.entropy);
}

SCOPE_TEST(entropyAll00) {
  auto hasher = make_unique_del(
    sfhash_create_hasher(ENTROPY),
    sfhash_destroy_hasher
  );

  const uint8_t buf[1024] = {0};

  sfhash_update_hasher(hasher.get(), std::begin(buf), std::end(buf));

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  SCOPE_ASSERT_EQUAL(0.0, hashes.entropy);
}

SCOPE_TEST(entropyAllFF) {
  auto hasher = make_unique_del(
    sfhash_create_hasher(ENTROPY),
    sfhash_destroy_hasher
  );

  uint8_t buf[1024];
  std::fill(std::begin(buf), std::end(buf), 0xFF);

  sfhash_update_hasher(hasher.get(), std::begin(buf), std::end(buf));

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  SCOPE_ASSERT_EQUAL(0.0, hashes.entropy);
}

SCOPE_TEST(entropyEqual) {
  auto hasher = make_unique_del(
    sfhash_create_hasher(ENTROPY),
    sfhash_destroy_hasher
  );

  uint8_t buf[1024];
  for (uint32_t i = 0; i < sizeof(buf); ++i) {
    buf[i] = i & 0xFF;
  }

  sfhash_update_hasher(hasher.get(), std::begin(buf), std::end(buf));

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
  SCOPE_ASSERT_EQUAL(8.0, hashes.entropy);
}
