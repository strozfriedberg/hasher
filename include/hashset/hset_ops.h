#pragma once

#include "error.h"
#include "hset_decoder.h"
#include "throw.h"
#include "hasher/hashset.h"

#include <cstddef>
#include <vector>
#include <utility>

void collect_hash_types(const auto& fields, auto& types) {
  for (const auto& rfd: fields) {
    types.emplace(
      static_cast<SFHASH_HashAlgorithm>(rfd.type),
      rfd.length
    );
  }
}

void make_output_records(const uint8_t* ibeg, const uint8_t* iend, size_t irlen, const auto& ofields, std::vector<std::vector<uint8_t>>& out) {
  for (const uint8_t* ir = ibeg; ir < iend; ir += irlen) {
    std::vector<uint8_t> orec;
    for (const auto& [i, hlen]: ofields) {
      if (i == -1) {
        orec.insert(orec.end(), 1 + hlen, 0);
      }
      else {
        const uint8_t* f = static_cast<const uint8_t*>(sfhash_hashset_record_field(reinterpret_cast<const SFHASH_HashsetRecord*>(ir), i));
        orec.insert(orec.end(), f, f + 1 + hlen);
      }
    }
    out.push_back(std::move(orec));
  }
}

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> union_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> intersect_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> difference_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat
);
