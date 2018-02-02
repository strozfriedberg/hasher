#include <scope/test.h>

#include "entropy.h"
#include "entropy_impl.h"
#include "util.h"

#include <algorithm>
#include <numeric>


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

  sfhash_update_entropy(entropy.get(), std::begin(buf), std::end(buf));

  SCOPE_ASSERT_EQUAL(0.0, sfhash_get_entropy(entropy.get()));
}

SCOPE_TEST(entropyAllFF) {
  auto entropy = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  uint8_t buf[1024];
  std::fill(std::begin(buf), std::end(buf), 0xFF);

  sfhash_update_entropy(entropy.get(), std::begin(buf), std::end(buf));

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

  sfhash_update_entropy(entropy.get(), std::begin(buf), std::end(buf));

  SCOPE_ASSERT_EQUAL(8.0, sfhash_get_entropy(entropy.get()));
}

SCOPE_TEST(entropyAccumulate) {
  auto a = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  auto b = make_unique_del(
    sfhash_create_entropy(),
    sfhash_destroy_entropy
  );

  std::iota(std::begin(b->hist), std::end(b->hist), 1);

  sfhash_accumulate_entropy(a.get(), b.get());

  SCOPE_ASSERT(std::equal(std::begin(a->hist), std::end(a->hist), std::begin(b->hist)));

  sfhash_accumulate_entropy(a.get(), b.get());

  for (size_t i = 0; i < 256; ++i) {
    SCOPE_ASSERT_EQUAL(a->hist[i], 2 * b->hist[i]);
  }
}
