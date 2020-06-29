#include <algorithm>
#include <cstring>

#include "hasher/api.h"
#include "error.h"
#include "hashset.h"
#include "hashset_util.h"
#include "throw.h"
#include "util.h"

using Error = SFHASH_Error;
using HashSet = SFHASH_HashSet;
using HashSetInfo = SFHASH_HashSetInfo;

// adaptor for use with hashset_dispatcher
template <size_t HashLength>
struct MakeHashSet {
  template <class... Args>
  auto operator()(Args&&... args) {
    return make_hashset<HashLength>(std::forward<Args>(args)...);
  }
};

HashSet* load_hashset(const HashSetInfo* hsinfo, const void* beg, const void* end, bool shared) {
  THROW_IF(beg > end, "beg > end!");

  const size_t exp_len = hsinfo->hashset_size * hsinfo->hash_length;
  const size_t act_len = static_cast<const char*>(end) - static_cast<const char*>(beg);

  THROW_IF(exp_len > act_len, "out of data reading hashes");
  THROW_IF(exp_len < act_len, "data trailing hashes");

  return hashset_dispatcher<MakeHashSet>(
    hsinfo->hash_length, beg, end, hsinfo->radius, shared
  );
}

HashSet* sfhash_load_hashset(
  const HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  bool shared,
  Error** err)
{
  try {
    return load_hashset(hsinfo, beg, end, shared);
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

void sfhash_destroy_hashset(HashSet* hset) { delete hset; }

bool sfhash_lookup_hashset(const HashSet* hset, const void* hash) {
  return hset->contains(static_cast<const uint8_t*>(hash));
}

uint32_t expected_index(const uint8_t* h, uint32_t set_size) {
  /*
   * The expected index for a hash (assuming a uniform distribution) in
   * the hash set is hash/2^(hash length) * set_size. We assume that
   * set_size fits in 32 bits, so nothing beyond the most significant 32
   * bits of the hash can make a difference for the expected index. Hence,
   * we can simplify the expected index to high/2^32 * set_size =
   * (high * set_size)/2^32. Observing that (2^32-1)^2 < (2^32)^2 = 2^64,
   * we see that (high * set_size) fits into 64 bits without overflow, so
   * can compute the expected index as (high * set_size) >> 32.
   */
  const uint64_t high32 = to_uint_be<uint32_t>(h);
  return static_cast<uint32_t>((high32 * set_size) >> 32);
}
