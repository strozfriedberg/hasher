#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

#include "hasher/hashset.h"

//#include <ranges>

/*
size_t encode_hset(
  const auto&& hashset_name,
  const auto&& hashset_desc,
  std::ranges::input_range auto&& hash_type_names,
  std::ranges::input_range auto&& in,
  std::ostream& out
);
*/

struct HashInfo {
  SFHASH_HashAlgorithm type;
  std::string name;
  uint32_t length;
  void (*conv)(uint8_t* dst, const char* src, size_t dlen);
};

struct SFHASH_HashsetBuildCtx {
  std::string hashset_name;
  std::string hashset_desc;
  std::vector<HashInfo> hash_infos;
  std::vector<std::vector<std::vector<char>>> records;
};

size_t write_hashset(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* htypes,
  size_t htypes_len,
  std::istream& in,
  std::ostream& out
);
