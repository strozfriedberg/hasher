#include "hasher/hashset.h"

#include "error.h"
#include "hashset_util.h"
#include "hset.h"
#include "lookupstrategy.h"
#include "hsd_impls/basic_hsd.h"

#include <algorithm>
#include <memory>

SFHASH_Hashset* sfhash_load_hashset(
  const void* beg,
  const void* end,
  SFHASH_Error** err
) {
  try {
    return new SFHASH_Hashset{
      parse_hset(
        static_cast<const char*>(beg),
        static_cast<const char*>(end)
      )
    };
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

void sfhash_destroy_hashset(SFHASH_Hashset* hset) {
  delete hset;
};

int sfhash_hashset_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashsetType htype
) {
  const auto i = std::find_if(
    hset->hsets.begin(),
    hset->hsets.end(),
    [htype](const auto& t) { return htype == std::get<0>(t).hash_type; }
  );

  return i == hset->hsets.end() ? -1 : i - hset->hsets.begin();
}

template <size_t HashLength>
struct Make_BLS {
  template <class... Args>
  LookupStrategy* operator()(Args&&... args) {
    return new BasicLookupStrategy<HashLength>(std::forward<Args>(args)...);
  }
};

bool sfhash_hashset_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
) {
  const auto& hs = hset->hsets[tidx];
  const auto& hsh = std::get<0>(hs);
  const auto& hsd = std::get<1>(hs);

  std::unique_ptr<HashSetData> impl(hashset_dispatcher<Make_BHSDI>(
    hsh.hash_length, hsd.beg, hsd.end
  ));
  return impl->contains(static_cast<const uint8_t*>(hash));
}
