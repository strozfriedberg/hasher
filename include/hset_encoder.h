#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <utility>
#include <vector>

#include "hasher/hasher.h"
#include "hasher/hashset.h"
#include "rwutil.h"

struct HashInfo {
  SFHASH_HashAlgorithm type;
  std::string name;
  uint32_t length;
  void (*conv)(uint8_t* dst, const char* src, size_t dlen);
};

struct SFHASH_HashsetBuildCtx {
  std::string hashset_name;
  std::string hashset_desc;
  std::string timestamp;
  std::vector<HashInfo> hash_infos;
  std::vector<std::vector<std::vector<uint8_t>>> records;
};

size_t write_hashset(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* htypes,
  size_t htypes_len,
  std::istream& in,
  std::vector<uint8_t>& out
);

size_t write_hashset(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* htypes,
  size_t htypes_len,
  std::istream& in,
  std::ostream& out
);

void size_to_u64(uint8_t* dst, const char* src, size_t dlen);

SFHASH_HashValues hash_chunk_data(
  const char* chunk_beg,
  const char* chunk_end
);

template <auto func, typename... Args>
size_t write_chunk(
  char* out,
  const char* chunk_type,
  Args&&... args)
{
  const char* beg = out;
  out += write_bytes(chunk_type, 4, out);

  char* lbeg = out;
  out += 8; // skip length
  char* dbeg = out;

  out += func(std::forward<Args>(args)..., out);

  write_le<uint64_t>(out - dbeg, lbeg); // data length

  const auto hashes = hash_chunk_data(dbeg, out);
  out += write_bytes(hashes.Sha2_256, sizeof(hashes.Sha2_256), out);
  return out - beg;
}

size_t length_alignment_padding(uint64_t pos, uint64_t align);

size_t write_alignment_padding(uint64_t pos, uint64_t align, char* out);

size_t length_magic();

size_t write_magic(char* out);

size_t length_fhdr_data(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp
);

size_t length_fhdr(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp
);

size_t write_fhdr_data(
  uint32_t version,
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  char* out
);

size_t write_fhdr(
  uint32_t version,
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  char* out
);

size_t length_hhnn_data(
  const HashInfo& hi
);

size_t length_hhnn(
  const HashInfo& hi
);

size_t write_hhnn_data(
  const HashInfo& hi,
  size_t hash_count,
  char* out
);

size_t write_hhnn(
  const HashInfo& hi,
  size_t hash_count,
  char* out
);

size_t length_hint_data();

size_t length_hint();

size_t write_hint_data(
  const std::vector<std::pair<int64_t, int64_t>>& block_bounds,
  char* out
);

size_t write_hint(
  const std::vector<std::pair<int64_t, int64_t>>& block_bounds,
  char* out
);

size_t length_hdat_data(size_t hash_count, size_t hash_size);

size_t length_hdat(size_t hash_count, size_t hash_size);

size_t write_hdat_data(
  const std::vector<std::vector<uint8_t>>& hashes,
  char* out
);

size_t write_hdat(
  const std::vector<std::vector<uint8_t>>& hashes,
  char* out
);

size_t length_ridx_data(size_t record_count);

size_t length_ridx(size_t record_count);

size_t write_ridx_data(
  const std::vector<uint64_t>& ridx,
  char* out
);

size_t write_ridx(
  const std::vector<uint64_t>& ridx,
  char* out
);

size_t length_rhdr_data(
  const std::vector<HashInfo>& hash_infos
);

size_t length_rhdr(
  const std::vector<HashInfo>& hash_infos
);

size_t write_rhdr_data(
  const std::vector<HashInfo>& hash_infos,
  uint64_t record_count,
  char* out
);

size_t write_rhdr(
  const std::vector<HashInfo>& hash_infos,
  uint64_t record_count,
  char* out
);

size_t length_rdat_data(
  const std::vector<HashInfo>& hash_infos,
  size_t record_count
);

size_t length_rdat(
  const std::vector<HashInfo>& hash_infos,
  size_t record_count
);

size_t write_rdat_data(
  const std::vector<HashInfo>& hash_infos,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out
);

size_t write_rdat(
  const std::vector<HashInfo>& hash_infos,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out
);

size_t length_ftoc_data(size_t chunk_count);

size_t length_ftoc(size_t chunk_count);

size_t write_ftoc_data(
  const std::vector<std::pair<uint64_t, std::string>>& toc,
  char* out
);

size_t write_ftoc(
  const std::vector<std::pair<uint64_t, std::string>>& toc,
  char* out
);
