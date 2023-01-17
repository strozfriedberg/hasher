#include "hset_decoder.h"
#include "hasher/hashset.h"

struct SFHASH_Hashset {
  Holder holder;
};

struct SFHASH_HashsetRecord {
};

int hashset_record_field_index_for_type(
  const RecordHeader& rhdr,
  SFHASH_HashAlgorithm htype
);
