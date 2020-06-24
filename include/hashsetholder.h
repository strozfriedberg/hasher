#pragma once

#include "hasher/api.h"
#include "hashset.h"
#include "throw.h"
#include "util.h"

#include <memory>

struct SFHASH_HashSetHolder {
  std::unique_ptr<SFHASH_HashSetInfo, void (*)(SFHASH_HashSetInfo*)> info;
  std::unique_ptr<SFHASH_HashSet, void (*)(SFHASH_HashSet*)> hset;

  void load(void* ptr, size_t len, bool shared) {
    char* p = static_cast<char*>(ptr);

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
};
