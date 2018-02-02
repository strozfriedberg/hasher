#include <scope/test.h>

#include "entropy.h"
#include "entropy_impl.h"
#include "util.h"

#include <algorithm>


SCOPE_TEST(entropyNoUpdate) {
  auto entropy = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  SCOPE_ASSERT_EQUAL(0.0 , sfhash_get_entropy(entropy.get()));
}

SCOPE_TEST(entropyEmptyUpdate) {
  auto entropy = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  sfhash_update_entropy(entropy.get(), nullptr, nullptr);

  SCOPE_ASSERT_EQUAL(0.0, sfhash_get_entropy(entropy.get()));
}

SCOPE_TEST(entropyAll00) {
  auto entropy = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  const uint8_t buf[1024] = {0};

  sfhash_update_entropy(entropy.get(), buf, buf + sizeof(buf));

  SCOPE_ASSERT_EQUAL(0.0, sfhash_get_entropy(entropy.get()));
}

SCOPE_TEST(entropyAllFF) {
  auto entropy = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  uint8_t buf[1024];
  std::fill(buf, buf + sizeof(buf), 0xFF);

  sfhash_update_entropy(entropy.get(), buf, buf + sizeof(buf));

  SCOPE_ASSERT_EQUAL(0.0, sfhash_get_entropy(entropy.get()));
}

SCOPE_TEST(entropyEqual) {
  auto entropy = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  uint8_t buf[1024];
  for (uint32_t i = 0; i < sizeof(buf); ++i) {
    buf[i] = i & 0xFF;
  }

  sfhash_update_entropy(entropy.get(), buf, buf + sizeof(buf));

  SCOPE_ASSERT_EQUAL(8.0, sfhash_get_entropy(entropy.get()));
}
