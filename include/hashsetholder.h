#pragma once

#include "hasher/api.h"
#include "hashset.h"

#include <memory>

struct SFHASH_HashSetHolder {
  std::unique_ptr<SFHASH_HashSetInfo, void (*)(SFHASH_HashSetInfo*)> info;
  std::unique_ptr<SFHASH_HashSet, void (*)(SFHASH_HashSet*)> hset;

  void load(const void* ptr, size_t len, bool shared);
};
