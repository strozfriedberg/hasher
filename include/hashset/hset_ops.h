#pragma once

#include "error.h"
#include "hset_decoder.h"
#include "throw.h"
#include "hasher/hashset.h"

#include <algorithm>
#include <cstring>
#include <cstddef>
#include <iterator>
#include <set>
#include <vector>
#include <utility>

void collect_hash_types(const auto& fields, auto& types) {
  for (const auto& rfd: fields) {
    types.emplace(
      static_cast<SFHASH_HashAlgorithm>(rfd.hash_type),
      rfd.hash_length
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

template <auto op>
std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> apply_op(
  const RecordHeader& lrhdr,
  const RecordData& lrdat,
  const RecordHeader& rrhdr,
  const RecordData& rrdat)
{
  // collect the hash types from the input hashsets
  std::set<std::pair<SFHASH_HashAlgorithm, size_t>> ltypes, rtypes;

  collect_hash_types(lrhdr.fields, ltypes);
  collect_hash_types(rrhdr.fields, rtypes);

  THROW_IF(
    ltypes != rtypes,
    "hash type mismatch between left and right operands"
  );

  std::vector<std::pair<SFHASH_HashAlgorithm, size_t>> otypes;

  // output types is the union of the left and right input types
  std::set_union(
    ltypes.begin(), ltypes.end(),
    rtypes.begin(), rtypes.end(),
    std::back_inserter(otypes)
  );

  // create mapping from output fields to input fields
  std::vector<std::pair<int, size_t>> lf, rf;
  for (const auto& [a, hlen]: otypes) {
    lf.emplace_back(hashset_record_field_index_for_type(lrhdr, a), hlen);
    rf.emplace_back(hashset_record_field_index_for_type(rrhdr, a), hlen);
  }

  std::vector<std::vector<uint8_t>> l_ex, r_ex;

  // rewrite left records to joint format
  make_output_records(
    static_cast<const uint8_t*>(lrdat.beg),
    static_cast<const uint8_t*>(lrdat.end),
    lrhdr.record_length,
    lf,
    l_ex
  );

  // rewrite right records to joint format
  make_output_records(
    static_cast<const uint8_t*>(rrdat.beg),
    static_cast<const uint8_t*>(rrdat.end),
    rrhdr.record_length,
    rf,
    r_ex
  );

  // ensure that the records to be unioned are sorted and unique
  std::sort(l_ex.begin(), l_ex.end());
  l_ex.erase(std::unique(l_ex.begin(), l_ex.end()), l_ex.end());

  std::sort(r_ex.begin(), r_ex.end());
  r_ex.erase(std::unique(r_ex.begin(), r_ex.end()), r_ex.end());

  // apply the op to the records
  std::vector<std::vector<uint8_t>> u;

  op(
    l_ex.begin(), l_ex.end(),
    r_ex.begin(), r_ex.end(),
    std::back_inserter(u)
  );

  // make the list of output types
  std::vector<SFHASH_HashAlgorithm> htypes;
  std::transform(
    otypes.begin(), otypes.end(),
    std::back_inserter(htypes),
    [](const auto& h) {
      return h.first;
    }
  );

  return { std::move(u), std::move(htypes) };
}
