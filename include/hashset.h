#pragma once

#include "hasher/api.h"
#include "hashsetdata.h"
#include "hashsetinfo.h"
#include "util.h"

#include <ctime>
#include <cstring>
#include <memory>

struct SFHASH_HashSet {
  std::unique_ptr<SFHASH_HashSetInfo, void (*)(SFHASH_HashSetInfo*)> info;
  std::unique_ptr<SFHASH_HashSetData, void (*)(SFHASH_HashSetData*)> hset;

  void load(const void* ptr, size_t len, bool shared);
};

char* to_iso8601(std::time_t tt);

const size_t HEADER_END = 4096;
const size_t HASHSET_OFF = HEADER_END;

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
