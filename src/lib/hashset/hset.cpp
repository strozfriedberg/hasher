#include "hasher/hashset.h"

#include "error.h"
#include "hashset/hset.h"
#include "hashset/lookupstrategy.h"

#include <algorithm>
#include <memory>
#include <numeric>

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

const char* sfhash_hashset_name(const SFHASH_Hashset* hset) {
  return hset->holder.fhdr.name.c_str();
}

const char* sfhash_hashset_description(const SFHASH_Hashset* hset) {
  return hset->holder.fhdr.desc.c_str();
}

const char* sfhash_hashset_timestamp(const SFHASH_Hashset* hset) {
  return hset->holder.fhdr.time.c_str();
}

const void* sfhash_hashset_sha2_256(const SFHASH_Hashset* hset) {
  return hset->holder.fhdr.sha2_256.data();
}

uint64_t sfhash_hashset_count(
  const SFHASH_Hashset* hset,
  size_t tidx)
{
  return std::get<HashsetHeader>(hset->holder.hsets[tidx]).hash_count;
}

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

int hashset_record_field_index_for_type(
  const RecordHeader& rhdr,
  SFHASH_HashAlgorithm htype
) {
  const auto i = std::find_if(
    rhdr.fields.begin(),
    rhdr.fields.end(),
    [htype](const auto& rfd) {
      return htype == rfd.type;
    }
  );

// TODO: consider storing this rather than computing it each time
  return i == rhdr.fields.end() ? -1 :
    std::accumulate(
      rhdr.fields.begin(), i, 0,
      [](int off, const auto& rfd) {
        return off + 1 + rfd.length;
      }
    );
}

int sfhash_hashset_record_field_index_for_type(
  const SFHASH_Hashset* hset,
  SFHASH_HashAlgorithm htype
) {
  return hashset_record_field_index_for_type(hset->holder.rhdr, htype);
}

const void* sfhash_hashset_record_field(
  const SFHASH_HashsetRecord* rec,
  size_t tidx
) {
  return reinterpret_cast<const uint8_t*>(rec) + tidx;
}

const SFHASH_HashsetRecordRange sfhash_hashset_records_lookup(
  const SFHASH_Hashset* /* hset */,
  size_t /* tidx */,
  const void* /* hash */
) {
// TODO: std::binary_search doesn't return a location, so we have nothing
// to use yet to implement this; maybe we need std::lower_bound?
  return {};
}

const SFHASH_HashsetRecord* sfhash_hashset_record_for_hash(
  const SFHASH_Hashset* hset,
  size_t tidx,
  size_t ridx
) {
  const auto& ri = std::get<ConstRecordIndex>(hset->holder.hsets[tidx]);
  const auto record_index = static_cast<const uint64_t*>(ri.beg)[ridx];
  return reinterpret_cast<const SFHASH_HashsetRecord*>(static_cast<const uint8_t*>(hset->holder.rdat.beg) + record_index * hset->holder.rhdr.record_length);
}
