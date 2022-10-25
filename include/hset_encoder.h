#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

#include "hasher/hashset.h"

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

void size_to_u64(uint8_t* dst, const char* src, size_t dlen);

struct Writer {
  ssize_t (*write_func)(void*, const void*, size_t);
  void* wctx;

  void write(const void* buf, size_t len) {
    write_func(wctx, buf, len);
  }
};

size_t write_chunk(
  const char* chunk_type,
  const char* chunk_bytes,
  size_t chunk_length,
  Writer& out
);
