#include "hasher/hashset.h"

#include "error.h"
#include "hashset/hset.h"
#include "hashset/lookupstrategy.h"

#include <algorithm>
#include <memory>

SFHASH_Hashset* sfhash_load_hashset(
  const void* beg,
  const void* end,
  SFHASH_Error** err
) {
  try {
    return new SFHASH_Hashset{
      decode_hset(
        static_cast<const uint8_t*>(beg),
        static_cast<const uint8_t*>(end)
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
  SFHASH_HashAlgorithm htype
) {
  const auto i = std::find_if(
    hset->holder.hsets.begin(),
    hset->holder.hsets.end(),
    [htype](const auto& t) {
      return htype == std::get<HashsetHeader>(t).hash_type;
    }
  );

  return i == hset->holder.hsets.end() ? -1 : i - hset->holder.hsets.begin();
}

bool sfhash_hashset_lookup(
  const SFHASH_Hashset* hset,
  size_t tidx,
  const void* hash
) {
  return std::get<std::unique_ptr<LookupStrategy>>(hset->holder.hsets[tidx])->contains(static_cast<const uint8_t*>(hash));
}
