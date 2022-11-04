#include "error.h"
#include "util.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <set>
#include <utility>
#include <vector>

#include <iostream>

#include "hex.h"

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

/*
bool mergeable(
  const std::vector<std::pair<size_t, size_t>>& ctypes_offs,
  const auto& a, const auto& b)
{
  for (const auto& [off, len]: ctypes_offs) {
    if (a[off] && b[off] && std::memcmp(&a[off], &b[off], len) != 0) {
      // both are present, and disagree
      return false;
    }
  }
  return true;
};

template <typename Itr>
Itr unique_partial(
  const std::vector<std::pair<size_t, size_t>>& ctypes_offs,
  Itr beg,
  Itr end)
{
  auto last = end;
  auto first = beg;
  auto dst = first;

  while (++first != last) {
    if (mergeable(ctypes_offs, *dst, *first)) {
      // if *dst, *first are mergeable, then there are no fields where they
      // conflict so bitwise OR acts as a merge operator
      std::transform(
        dst->begin(), dst->end(),
        first->begin(),
        dst->begin(),
        [](char d, char f) { return d | f; }
      );
    }
    else {
      ++dst;
      if (dst != first) {
        *dst = std::move(*first);
      }
    }
  }

  return ++dst;
}

template <typename Itr>
Itr unique_full(
  const std::vector<std::pair<size_t, size_t>>& ctypes_offs,
  Itr beg,
  Itr end)
{
  return std::unique(beg, end);
}

void merge_equal_records(
  const std::vector<std::pair<size_t, size_t>>& ctypes_offs,
  bool partial_matches_equal,
  auto& out)
{
  // merge equal records
  using Itr = decltype(out.begin());
  out.erase(
    (partial_matches_equal ? unique_partial<Itr> : unique_full<Itr>)(
      ctypes_offs, out.begin(), out.end()
    )
  );
}
*/

template <auto op>
SFHASH_HashsetBuildCtx* setop_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  SFHASH_Error** err)
{
  // collect the hash types from the input hashsets
  std::set<std::pair<SFHASH_HashAlgorithm, size_t>> ltypes, rtypes;

  collect_hash_types(l->holder.rhdr.fields, ltypes);
  collect_hash_types(r->holder.rhdr.fields, rtypes);

  if (ltypes != rtypes) {
    fill_error(err, "hash type mismatch between left and right operands");
    return nullptr;
  }

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
    lf.emplace_back(sfhash_hashset_record_field_index_for_type(l, a), hlen);
    rf.emplace_back(sfhash_hashset_record_field_index_for_type(r, a), hlen);
  }

  std::vector<std::vector<uint8_t>> l_ex, r_ex;

  // rewrite left records to joint format
  make_output_records(
    static_cast<const uint8_t*>(l->holder.rdat.beg),
    static_cast<const uint8_t*>(l->holder.rdat.end),
    l->holder.rhdr.record_length,
    lf,
    l_ex
  );

  // rewrite right records to joint format
  make_output_records(
    static_cast<const uint8_t*>(r->holder.rdat.beg),
    static_cast<const uint8_t*>(r->holder.rdat.end),
    r->holder.rhdr.record_length,
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

  auto bctx = make_unique_del(
    sfhash_save_hashset_open(
      result_hashset_name,
      result_hashset_desc,
      htypes.data(),
      htypes.size(),
      err
    ),
    sfhash_save_hashset_destroy
  );

  if (*err) {
    return nullptr;
  }

  for (const auto& r: u) {
    sfhash_add_hashset_record(bctx.get(), r.data());
  }

  return bctx.release();
}

SFHASH_HashsetBuildCtx* sfhash_union_hashsets_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  SFHASH_Error** err)
{
  return setop_open<
    std::set_union<
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::back_insert_iterator<std::vector<std::vector<uint8_t>>>
    >
  >(l, r, result_hashset_name, result_hashset_desc, err);
}

SFHASH_HashsetBuildCtx* sfhash_intersect_hashsets_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  SFHASH_Error** err)
{
  return setop_open<
    std::set_intersection<
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::back_insert_iterator<std::vector<std::vector<uint8_t>>>
    >
  >(l, r, result_hashset_name, result_hashset_desc, err);
}

SFHASH_HashsetBuildCtx* sfhash_subtract_hashsets_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  SFHASH_Error** err)
{
  return setop_open<
    std::set_difference<
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::back_insert_iterator<std::vector<std::vector<uint8_t>>>
    >
  >(l, r, result_hashset_name, result_hashset_desc, err);
}
