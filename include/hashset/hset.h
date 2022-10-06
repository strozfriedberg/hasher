#include "hset_decoder.h"
#include "hashset/lookupstrategy.h"

#include <memory>

struct SFHASH_Hashset {
  Holder holder;
  std::unique_ptr<LookupStrategy> lookup;
};
