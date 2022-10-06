#include <tuple>
#include <utility>

#include "lookupstrategy.h"
#include "hashset_util.h"
#include "hset.h"
#include "throw.h"
#include "util.h"

#include "hashset/radius_ls.h"

template <size_t HashLength>
LookupStrategy* make_lookup_strategy(
  const void* beg,
  const void* end,
  uint32_t radius)
{
  return make_radius_lookup_strategy<HashLength>(beg, end, radius);
}

// adaptor for use with hashset_dispatcher
template <size_t HashLength>
struct MakeLookupStrategy {
  template <class... Args>
  auto operator()(Args&&... args) {
    return make_lookup_strategy<HashLength>(std::forward<Args>(args)...);
  }
};

LookupStrategy* load_lookup_strategy(const SFHASH_Hashset* hset, size_t tidx) {
  THROW_IF(!hset, "hset == nullptr");

  const auto& hdr = std::get<0>(hset->hsets[tidx]);
  const auto& dat = std::get<1>(hset->hsets[tidx]);

  const size_t exp_len = hdr.hash_length * hdr.hash_count;
  const size_t act_len = static_cast<const char*>(dat.end) - static_cast<const char*>(dat.beg);

  THROW_IF(exp_len > act_len, "out of data reading hashes");
  THROW_IF(exp_len < act_len, "data trailing hashes");

// TODO: radius arg: use the hint
  return hashset_dispatcher<MakeLookupStrategy>(
    hdr.hash_length, dat.beg, dat.end, 0 
  );
}
