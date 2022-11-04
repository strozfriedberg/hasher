#include "error.h"
#include "util.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_ops.h"

#include <iostream>

#include "hex.h"

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
  try {
    const auto [u, htypes] = apply_op<op>(
      l->holder.rhdr,
      l->holder.rdat,
      r->holder.rhdr,
      r->holder.rdat
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
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
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
