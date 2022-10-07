#include "hasher/hashset.h"

#include "error.h"
#include "hashset_util.h"
#include "hashset/basic_ls.h"
#include "hashset/hset.h"
#include "hashset/lookupstrategy.h"

#include <algorithm>
#include <memory>

template <size_t HashLength>
struct Make_BLS {
  template <class... Args>
  LookupStrategy* operator()(Args&&... args) {
    return new BasicLookupStrategy<HashLength>(std::forward<Args>(args)...);
  }
};

std::unique_ptr<LookupStrategy> make_lookup_strategy(
  const HashsetHeader& hsh,
  const HashsetHint& hnt,
  const HashsetData& hsd)
{
  switch (hnt.hint_type) {
  case HintType::RADIUS:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  case HintType::RANGE:
    return std::unique_ptr<LookupStrategy>(

      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  case HintType::BLOCK:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  case HintType::BLOCK_LINEAR:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  default:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  }
}

SFHASH_Hashset* sfhash_load_hashset(
  const void* beg,
  const void* end,
  SFHASH_Error** err
) {
  std::unique_ptr<SFHASH_Hashset> hset;

  try {
    hset.reset(new SFHASH_Hashset{
      parse_hset(
        static_cast<const char*>(beg),
        static_cast<const char*>(end)
      )
    });
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }

  // set up the lookup strategies
  for (auto& [hsh, hsd, hnt, ls, _]: hset->holder.hsets) {
    ls = make_lookup_strategy(hsh, hsd, hnt);
  }

  return hset.release();
}

void sfhash_destroy_hashset(SFHASH_Hashset* hset) {
  delete hset;
};

int sfhash_hashset_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashsetType htype
) {
  const auto i = std::find_if(
    hset->holder.hsets.begin(),
    hset->holder.hsets.end(),
    [htype](const auto& t) { return htype == std::get<0>(t).hash_type; }
  );

  return i == hset->holder.hsets.end() ? -1 : i - hset->holder.hsets.begin();
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
