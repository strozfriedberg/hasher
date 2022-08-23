#include <algorithm>
#include <cstring>
#include <limits>

#include "hasher/api.h"
#include "hashsetdata.h"
#include "hashset_util.h"
#include "throw.h"
#include "util.h"

#include "hsd_impls/radius_hsd.h"

using HashSetInfo = SFHASH_HashSetInfo;

template <size_t HashLength>
HashSetData* make_hashset_data(
  const void* beg,
  const void* end,
  uint32_t radius)
{
  return make_radius_hashset_data<HashLength>(beg, end, radius);
}

// adaptor for use with hashset_dispatcher
template <size_t HashLength>
struct MakeHashSetData {
  template <class... Args>
  auto operator()(Args&&... args) {
    return make_hashset_data<HashLength>(std::forward<Args>(args)...);
  }
};

HashSetData* load_hashset_data(const HashSetInfo* hsinfo, const void* beg, const void* end) {
  THROW_IF(beg > end, "beg > end!");

  const size_t exp_len = hsinfo->hashset_size * hsinfo->hash_length;
  const size_t act_len = static_cast<const char*>(end) - static_cast<const char*>(beg);

  THROW_IF(exp_len > act_len, "out of data reading hashes");
  THROW_IF(exp_len < act_len, "data trailing hashes");

  return hashset_dispatcher<MakeHashSetData>(
    hsinfo->hash_length, beg, end, hsinfo->radius
  );
}
