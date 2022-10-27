#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <utility>
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

size_t length_alignment_padding(uint64_t pos, uint64_t align);

size_t write_alignment_padding(uint64_t pos, uint64_t align, char* out);

size_t write_alignment_padding(uint64_t pos, uint64_t align, Writer& out);

size_t length_magic();

size_t write_magic(char* out);

size_t length_fhdr(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp
);

size_t write_fhdr(
  uint32_t version,
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  char* out
);

size_t length_hhnn(
  const HashInfo& hi
);

size_t write_hhnn(
  const HashInfo& hi,
  size_t hash_count,
  char* out
);

size_t length_hint();

size_t write_hint(
  const std::vector<std::vector<uint8_t>>& hashes,
  char* out
);

size_t length_hdat(size_t hash_count, size_t hash_size);

size_t write_hdat(
  const std::vector<std::vector<uint8_t>>& hashes,
  char* out
);

size_t length_ridx(size_t record_count);

size_t write_ridx(
  const std::vector<uint64_t>& ridx,
  char* out
);

size_t length_rhdr(
  const std::vector<HashInfo>& hash_infos
);

size_t write_rhdr(
  const std::vector<HashInfo>& hash_infos,
  uint64_t record_count,
  char* out
);

size_t length_rdat(
  const std::vector<HashInfo>& hash_infos,
  size_t record_count
);

size_t write_rdat(
  const std::vector<HashInfo>& hash_infos,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out
);

size_t length_ftoc(size_t chunk_count);

size_t write_ftoc(
  const std::vector<std::pair<uint64_t, std::string>>& toc,
  char* out
);
