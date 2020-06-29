#include "hasher/api.h"
#include "hashsetholder.h"
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

void SFHASH_HashSetHolder::load(const void* ptr, size_t len, bool shared) {
  const uint8_t* p = static_cast<const uint8_t*>(ptr);

    SFHASH_Error* err = nullptr;

    info = make_unique_del(
      sfhash_load_hashset_info(p, p + len, &err),
      sfhash_destroy_hashset_info
    );

// FIXME: leaks err
    THROW_IF(err, err->message);

    hset = make_unique_del(
      sfhash_load_hashset(
        info.get(),
        p + info->hashset_off,
        p + info->hashset_off + info->hashset_size * info->hash_length,
        shared,
        &err
      ),
      sfhash_destroy_hashset
    );

// FIXME: leaks err
    THROW_IF(err, err->message);
}

SFHASH_HashSetHolder* sfhash_load_hashset_holder(
  const void* beg,
  const void* end,
  bool shared,
  SFHASH_Error** err)
{
  auto hset = make_unique_del(
    new SFHASH_HashSetHolder{{nullptr, nullptr}, {nullptr, nullptr}},
    sfhash_destroy_hashset_holder
  );

  const size_t len = static_cast<const uint8_t*>(end) -
                     static_cast<const uint8_t*>(beg);
  hset->load(beg, len, shared);

  return hset.release();
}

const SFHASH_HashSetInfo* sfhash_info_from_holder(
  const SFHASH_HashSetHolder* hset)
{
  return hset->info.get();
}

bool sfhash_lookup_hashset_holder(
  const SFHASH_HashSetHolder* hset,
  const void* hash)
{
  return hset->hset->contains(static_cast<const uint8_t*>(hash));
}

void sfhash_destroy_hashset_holder(SFHASH_HashSetHolder* hset) {
  delete hset;
}

const size_t HEADER_END = 4096;
const size_t HASHSET_OFF = HEADER_END;

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

template <class Itr>
std::unique_ptr<SFHASH_HashSetInfo, void(*)(SFHASH_HashSetInfo*)> make_info(
  const char* name,
  const char* desc,
  SFHASH_HashAlgorithm type,
  Itr dbeg,
  Itr dend)
{
  const uint32_t radius = compute_radius(dbeg, dend);

  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_SHA_2_256),
    sfhash_destroy_hasher
  );

  sfhash_update_hasher(hasher.get(), dbeg, dend);
  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  auto info = make_unique_del(
    new SFHASH_HashSetInfo{
        1,
        type,
        sfhash_hash_length(type),
        0,
        static_cast<uint64_t>(dend - dbeg),
        HASHSET_OFF,
        0,
        radius,
        {0},
        nullptr,
        nullptr,
        nullptr
    },
    sfhash_destroy_hashset_info
  );

/*
  info->version = 1;
  info->hash_type = type;
  info->hash_length = sfhash_hash_length(type);
  info->flags = 0;
  info->hashset_size = dend - dbeg;
  info->hashset_off = HASHSET_OFF;
  info->sizes_off = 0;
  info->radius = radius;
*/

  std::memcpy(info->hashset_sha256, hashes.Sha2_256, sizeof(hashes.Sha2_256));

  info->hashset_name = new char[std::strlen(name)+1];
  std::strcpy(info->hashset_name, name);

  info->hashset_time = to_iso8601(std::time(nullptr));

  info->hashset_desc = new char[std::strlen(desc)+1];
  std::strcpy(info->hashset_desc, desc);

  return info;
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

  size_t max_size(const SFHASH_HashSetHolder& l,
                  const SFHASH_HashSetHolder& r) const {
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

  size_t max_size(const SFHASH_HashSetHolder& l,
                  const SFHASH_HashSetHolder& r) const {
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

  size_t max_size(const SFHASH_HashSetHolder& l,
                  const SFHASH_HashSetHolder&) const {
    return HASHSET_OFF + l.info->hashset_size * l.info->hash_length;
  }
};

template <size_t HashLength, class Op>
std::unique_ptr<SFHASH_HashSetHolder, void (*)(SFHASH_HashSetHolder*)> set_op(
  Op op,
  const SFHASH_HashSetHolder& l,
  const SFHASH_HashSetHolder& r,
  void* outptr,
  bool shared,
  const char* oname,
  const char* odesc)
{
  auto out = reinterpret_cast<uint8_t*>(outptr);

  const auto lbeg = reinterpret_cast<IItr<HashLength>>(
    l.hset->data() + l.info->hashset_off
  );
  const auto rbeg = reinterpret_cast<IItr<HashLength>>(
    r.hset->data() + r.info->hashset_off
  );

  const auto lend = lbeg + l.info->hashset_size;
  const auto rend = rbeg + r.info->hashset_size;

  auto obeg = reinterpret_cast<OItr<HashLength>>(out + HASHSET_OFF);
  const auto oend = op(lbeg, lend, rbeg, rend, obeg);

  auto o = make_unique_del(
    new SFHASH_HashSetHolder{{nullptr, nullptr}, {nullptr, nullptr}},
    sfhash_destroy_hashset_holder
  );

  o->info = make_info(oname, odesc, l.info->hash_type, obeg, oend);
  write_header(o->info.get(), out, out + HEADER_END);

  o->hset = make_unique_del(
    load_hashset(o->info.get(), obeg, oend, shared),
    sfhash_destroy_hashset
  );

  return o;
}

template <size_t N>
struct UnionSetOp {
  std::unique_ptr<SFHASH_HashSetHolder, void (*)(SFHASH_HashSetHolder*)> operator()(
    const SFHASH_HashSetHolder& l,
    const SFHASH_HashSetHolder& r,
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
  std::unique_ptr<SFHASH_HashSetHolder, void (*)(SFHASH_HashSetHolder*)> operator()(
    const SFHASH_HashSetHolder& l,
    const SFHASH_HashSetHolder& r,
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
  std::unique_ptr<SFHASH_HashSetHolder, void (*)(SFHASH_HashSetHolder*)> operator()(
    const SFHASH_HashSetHolder& l,
    const SFHASH_HashSetHolder& r,
    void* outptr,
    bool shared,
    const char* oname,
    const char* odesc) const
  {
    return set_op<N>(DifferenceOp(), l, r, outptr, shared, oname, odesc);
  }
};

SFHASH_HashSetHolder* sfhash_union_hashsets(
  const SFHASH_HashSetHolder* l,
  const SFHASH_HashSetHolder* r,
  void* out,
  bool shared)
{
  return hashset_dispatcher<UnionSetOp>(
    l->info->hash_length, *l, *r, out, shared, "union", "union"
  ).release();
}

SFHASH_HashSetHolder* sfhash_intersect_hashsets(
  const SFHASH_HashSetHolder* l,
  const SFHASH_HashSetHolder* r,
  void* out,
  bool shared)
{
  return hashset_dispatcher<IntersectSetOp>(
    l->info->hash_length, *l, *r, out, shared, "intersection", "intersection"
  ).release();
}

SFHASH_HashSetHolder* sfhash_difference_hashsets(
  const SFHASH_HashSetHolder* l,
  const SFHASH_HashSetHolder* r,
  void* out,
  bool shared)
{
  return hashset_dispatcher<DifferenceSetOp>(
    l->info->hash_length, *l, *r, out, shared, "difference", "difference"
  ).release();
}
