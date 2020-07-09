#include "hasher/api.h"
#include "error.h"
#include "sizeset.h"
#include "throw.h"
#include "util.h"

using Error = SFHASH_Error;
using HashSetInfo = SFHASH_HashSetInfo;
using SizeSet = SFHASH_SizeSet;

SizeSet* load_sizeset(
  HashSetInfo* hsinfo,
  const uint8_t* beg,
  const uint8_t* end)
{
  THROW_IF(beg > end, "beg > end!");

  const size_t exp_len = hsinfo->hashset_size * sizeof(uint64_t);
  const size_t act_len = end - beg;

  THROW_IF(exp_len > act_len, "out of data reading sizes");
  THROW_IF(exp_len < act_len, "data trailing sizes");

  auto sset = make_unique_del(new SizeSet, sfhash_destroy_sizeset);

  const uint8_t* cur = beg;
  while (cur < end) {
    sset->sizes.insert(read_le_8(beg, cur, end));
  }

  return sset.release();
}

SizeSet* sfhash_load_sizeset(
  HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  Error** err)
{
  try {
    return load_sizeset(hsinfo, static_cast<const uint8_t*>(beg),
                                static_cast<const uint8_t*>(end));
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

bool sfhash_lookup_sizeset(const SizeSet* sset, uint64_t size) {
  return sset->sizes.find(size) != sset->sizes.end();
}

void sfhash_destroy_sizeset(SizeSet* sset) {
  delete sset;
}


