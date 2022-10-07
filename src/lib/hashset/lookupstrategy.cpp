#include <tuple>
#include <utility>

#include "hashset_util.h"
#include "throw.h"
#include "util.h"

#include "hashset/lookupstrategy.h"
#include "hashset/hset.h"
#include "hashset/radius_ls.h"

/*
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
*/
