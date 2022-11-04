#include "error.h"
#include "util.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_ops.h"

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
