#pragma once

#include "throw.h"

#include <cstdint>
#include <type_traits>

uint32_t expected_index(const uint8_t* h, uint32_t set_size);

template <template <size_t> class Func, class... Args>
auto hashset_dispatcher(size_t hash_length, Args&&... args)
{
  switch (hash_length) {
  case 4:
    return Func<4>()(std::forward<Args>(args)...);
  case 8:
    return Func<8>()(std::forward<Args>(args)...);
  case 16:
    return Func<16>()(std::forward<Args>(args)...);
  case 20:
    return Func<20>()(std::forward<Args>(args)...);
  case 28:
    return Func<28>()(std::forward<Args>(args)...);
  case 32:
    return Func<32>()(std::forward<Args>(args)...);
  case 48:
    return Func<48>()(std::forward<Args>(args)...);
  case 64:
    return Func<64>()(std::forward<Args>(args)...);
  default:
    THROW("unsupported hash length " << hash_length);
  }
}
