#include "error.h"
#include "hset_encoder.h"
#include "util.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_ops.h"

#include <algorithm>
#include <iterator>
#include <set>

template <auto op>
std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> apply_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
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

template <auto op>
SFHASH_HashsetBuildCtx* setop_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* temp_dir,
  const char* output_file,
  SFHASH_Error** err)
{
  try {
    check_strlen(result_hashset_name, "result_hashset_name");
    check_strlen(result_hashset_desc, "result_hashset_desc");

    const auto [u, htypes] = op(
      l->holder.rhdr,
      l->holder.rdat,
      r->holder.rhdr,
      r->holder.rdat
    );

    auto bctx = make_unique_del(
      sfhash_hashset_builder_open(
        result_hashset_name,
        result_hashset_desc,
        htypes.data(),
        htypes.size(),
        write_records,
        write_hashsets,
        temp_dir,
        output_file,
        err
      ),
      sfhash_hashset_builder_destroy
    );

    if (*err) {
      return nullptr;
    }

    for (const auto& r: u) {
      sfhash_hashset_builder_add_record(bctx.get(), r.data());
    }

    return bctx.release();
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> union_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  return apply_op<
    std::set_union<
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::back_insert_iterator<std::vector<std::vector<uint8_t>>>
    >
  >(
    lrhdr,
    lrdat,
    rrhdr,
    rrdat
  );
}

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> intersect_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  return apply_op<
    std::set_intersection<
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::back_insert_iterator<std::vector<std::vector<uint8_t>>>
    >
  >(
    lrhdr,
    lrdat,
    rrhdr,
    rrdat
  );
}

std::pair<
  std::vector<std::vector<uint8_t>>,
  std::vector<SFHASH_HashAlgorithm>
> difference_op(
  const RecordHeader& lrhdr,
  const ConstRecordData& lrdat,
  const RecordHeader& rrhdr,
  const ConstRecordData& rrdat)
{
  return apply_op<
    std::set_difference<
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::vector<std::vector<uint8_t>>::const_iterator,
      std::back_insert_iterator<std::vector<std::vector<uint8_t>>>
    >
  >(
    lrhdr,
    lrdat,
    rrhdr,
    rrdat
  );
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_union_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* temp_dir,
  const char* output_file,
  SFHASH_Error** err)
{
  return setop_open<union_op>(
    l,
    r,
    result_hashset_name,
    result_hashset_desc,
    write_records,
    write_hashsets,
    temp_dir,
    output_file,
    err
  );
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_intersect_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* temp_dir,
  const char* output_file,
  SFHASH_Error** err)
{
  return setop_open<intersect_op>(
    l,
    r,
    result_hashset_name,
    result_hashset_desc,
    write_records,
    write_hashsets,
    temp_dir,
    output_file,
    err
  );
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_subtract_open(
  const SFHASH_Hashset* l,
  const SFHASH_Hashset* r,
  const char* result_hashset_name,
  const char* result_hashset_desc,
  bool write_records,
  bool write_hashsets,
  const char* temp_dir,
  const char* output_file,
  SFHASH_Error** err)
{
  return setop_open<difference_op>(
    l,
    r,
    result_hashset_name,
    result_hashset_desc,
    write_records,
    write_hashsets,
    temp_dir,
    output_file,
    err
  );
}
