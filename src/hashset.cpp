#include "hasher/api.h"
#include "hashset.h"
#include "hashsetdata.h"
#include "hashsetinfo.h"
#include "hashset_util.h"
#include "throw.h"
#include "util.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <ctime>
#include <memory>
#include <type_traits>

void SFHASH_HashSet::load(const void* ptr, size_t len, bool shared) {
  const uint8_t* p = static_cast<const uint8_t*>(ptr);

    std::unique_ptr<SFHASH_Error> errptr;
    SFHASH_Error* err = nullptr;

    info = make_unique_del(
      sfhash_load_hashset_info(p, p + len, &err),
      sfhash_destroy_hashset_info
    );

    errptr.reset(err);
    THROW_IF(err, err->message);

    hset = make_unique_del(
      sfhash_load_hashset_data(
        info.get(),
        p + info->hashset_off,
        p + info->hashset_off + info->hashset_size * info->hash_length,
        shared,
        &err
      ),
      sfhash_destroy_hashset_data
    );

    errptr.reset(err);
    THROW_IF(err, err->message);
}

SFHASH_HashSet* sfhash_load_hashset(
  const void* beg,
  const void* end,
  bool shared,
  SFHASH_Error** err)
{
  auto hset = make_unique_del(
    new SFHASH_HashSet{{nullptr, nullptr}, {nullptr, nullptr}},
    sfhash_destroy_hashset
  );

  const size_t len = static_cast<const uint8_t*>(end) -
                     static_cast<const uint8_t*>(beg);
  hset->load(beg, len, shared);

  return hset.release();
}

const SFHASH_HashSetInfo* sfhash_info_for_hashset(
  const SFHASH_HashSet* hset)
{
  return hset->info.get();
}

bool sfhash_lookup_hashset(
  const SFHASH_HashSet* hset,
  const void* hash)
{
  return hset->hset->contains(static_cast<const uint8_t*>(hash));
}

void sfhash_destroy_hashset(SFHASH_HashSet* hset) {
  delete hset;
}

template <size_t HashLength>
using IItr = const std::array<uint8_t, HashLength>*;

template <size_t HashLength>
using OItr = std::array<uint8_t, HashLength>*;

char* to_iso8601(std::time_t tt) {
  const size_t maxlen = sizeof("0000-00-00T00:00:00Z") + 1;
  char* iso8601 = new char[maxlen];
  std::strftime(iso8601, maxlen, "%FT%TZ", std::gmtime(&tt));
  return iso8601;
}

struct UnionOp {
  template <size_t HashLength>
  OItr<HashLength> operator()(
    IItr<HashLength> lbeg,
    IItr<HashLength> lend,
    IItr<HashLength> rbeg,
    IItr<HashLength> rend,
    OItr<HashLength> obeg) const
  {
    return std::set_union(lbeg, lend, rbeg, rend, obeg);
  }

  size_t max_size(const SFHASH_HashSet& l,
                  const SFHASH_HashSet& r) const {
    return HASHSET_OFF + l.info->hashset_size * l.info->hash_length +
                         r.info->hashset_size * r.info->hash_length;
  }
};

struct IntersectOp {
  template <size_t HashLength>
  OItr<HashLength> operator()(
    IItr<HashLength> lbeg,
    IItr<HashLength> lend,
    IItr<HashLength> rbeg,
    IItr<HashLength> rend,
    OItr<HashLength> obeg) const
  {
    return std::set_intersection(lbeg, lend, rbeg, rend, obeg);
  }

  size_t max_size(const SFHASH_HashSet& l,
                  const SFHASH_HashSet& r) const {
    return HASHSET_OFF +
      std::max(l.info->hashset_size, r.info->hashset_size) *
      l.info->hash_length;
  }
};

struct DifferenceOp {
  template <size_t HashLength>
  OItr<HashLength> operator()(
    IItr<HashLength> lbeg,
    IItr<HashLength> lend,
    IItr<HashLength> rbeg,
    IItr<HashLength> rend,
    OItr<HashLength> obeg) const
  {
    return std::set_difference(lbeg, lend, rbeg, rend, obeg);
  }

  size_t max_size(const SFHASH_HashSet& l,
                  const SFHASH_HashSet&) const {
    return HASHSET_OFF + l.info->hashset_size * l.info->hash_length;
  }
};

template <size_t HashLength, class Op>
std::unique_ptr<SFHASH_HashSet, void (*)(SFHASH_HashSet*)> set_op(
  Op op,
  const SFHASH_HashSet& l,
  const SFHASH_HashSet& r,
  void* outptr,
  bool shared,
  const char* oname,
  const char* odesc)
{
  auto out = reinterpret_cast<uint8_t*>(outptr);

  const auto lbeg = reinterpret_cast<IItr<HashLength>>(l.hset->data());
  const auto rbeg = reinterpret_cast<IItr<HashLength>>(r.hset->data());

  const auto lend = lbeg + l.info->hashset_size;
  const auto rend = rbeg + r.info->hashset_size;

  auto obeg = reinterpret_cast<OItr<HashLength>>(out + HASHSET_OFF);
  const auto oend = op(lbeg, lend, rbeg, rend, obeg);

  auto o = make_unique_del(
    new SFHASH_HashSet{{nullptr, nullptr}, {nullptr, nullptr}},
    sfhash_destroy_hashset
  );

  o->info = make_info(oname, odesc, l.info->hash_type, obeg, oend);
  write_header(o->info.get(), out, out + HEADER_END);

  o->hset = make_unique_del(
    load_hashset_data(o->info.get(), obeg, oend, shared),
    sfhash_destroy_hashset_data
  );

  return o;
}

template <size_t N>
struct UnionSetOp {
  std::unique_ptr<SFHASH_HashSet, void (*)(SFHASH_HashSet*)> operator()(
    const SFHASH_HashSet& l,
    const SFHASH_HashSet& r,
    void* outptr,
    bool shared,
    const char* oname,
    const char* odesc) const
  {
    return set_op<N>(UnionOp(), l, r, outptr, shared, oname, odesc);
  }
};

template <size_t N>
struct IntersectSetOp {
  std::unique_ptr<SFHASH_HashSet, void (*)(SFHASH_HashSet*)> operator()(
    const SFHASH_HashSet& l,
    const SFHASH_HashSet& r,
    void* outptr,
    bool shared,
    const char* oname,
    const char* odesc) const
  {
    return set_op<N>(IntersectOp(), l, r, outptr, shared, oname, odesc);
  }
};

template <size_t N>
struct DifferenceSetOp {
  std::unique_ptr<SFHASH_HashSet, void (*)(SFHASH_HashSet*)> operator()(
    const SFHASH_HashSet& l,
    const SFHASH_HashSet& r,
    void* outptr,
    bool shared,
    const char* oname,
    const char* odesc) const
  {
    return set_op<N>(DifferenceOp(), l, r, outptr, shared, oname, odesc);
  }
};

SFHASH_HashSet* sfhash_union_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  bool shared,
  const char* out_name,
  const char* out_desc)
{
  return hashset_dispatcher<UnionSetOp>(
    l->info->hash_length, *l, *r, out, shared, out_name, out_desc
  ).release();
}

SFHASH_HashSet* sfhash_intersect_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  bool shared,
  const char* out_name,
  const char* out_desc)
{
  return hashset_dispatcher<IntersectSetOp>(
    l->info->hash_length, *l, *r, out, shared, out_name, out_desc
  ).release();
}

SFHASH_HashSet* sfhash_difference_hashsets(
  const SFHASH_HashSet* l,
  const SFHASH_HashSet* r,
  void* out,
  bool shared,
  const char* out_name,
  const char* out_desc)
{
  return hashset_dispatcher<DifferenceSetOp>(
    l->info->hash_length, *l, *r, out, shared, out_name, out_desc
  ).release();
}
