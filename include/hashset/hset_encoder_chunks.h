#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "rwutil.h"
#include "hashset/hset_structs.h"

struct binary_fuse8_s;
using binary_fuse8_t = binary_fuse8_s;

template <auto func, typename... Args>
size_t length_chunk(Args&&... args)
{
  return 4 + // chunk type
         8 + // chunk data length
         func(std::forward<Args>(args)...);
}

// C++20: template <auto func, typename... Args>
template <typename Func, typename... Args>
size_t write_chunk(
  Func func,
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

  return out - beg;
}

size_t length_alignment_padding(uint64_t pos, uint64_t align);

size_t write_alignment_padding(uint64_t pos, uint64_t align, char* out);

size_t length_magic();

size_t write_magic(char* out);

size_t length_hset_hash(); 

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

uint32_t make_hhnn_type(uint32_t hash_type);

std::string make_hhnn_str(uint32_t hash_type);

size_t length_hhnn_data(
  const RecordFieldDescriptor& hi
);

size_t length_hhnn(
  const RecordFieldDescriptor& hi
);

size_t write_hhnn_data(
  const RecordFieldDescriptor& hi,
  uint64_t hash_count,
  char* out
);

size_t write_hhnn(
  const RecordFieldDescriptor& hi,
  uint64_t hash_count,
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

size_t length_filter_data(uint64_t hash_count);

size_t length_filter(uint64_t hash_count);

size_t write_filter_data(const binary_fuse8_t* filter, char* out);

size_t write_filter(const binary_fuse8_t* filter, char* out);

size_t length_hdat_data(size_t hash_count, size_t hash_size);

size_t length_hdat(size_t hash_count, size_t hash_size);

size_t write_hdat_data(
  const HashsetData& hdat,
  char* out
);

size_t write_hdat(
  const HashsetData& hdat,
  char* out
);

size_t length_ridx_data(size_t record_count);

size_t length_ridx(size_t record_count);

size_t write_ridx_data(
  const RecordIndex& ridx,
  char* out
);

size_t write_ridx(
  const RecordIndex& ridx,
  char* out
);

size_t length_rhdr_data(
  const std::vector<RecordFieldDescriptor>& fields
);

size_t length_rhdr(
  const std::vector<RecordFieldDescriptor>& fields
);

size_t write_rhdr_data(
  const std::vector<RecordFieldDescriptor>& fields,
  uint64_t record_count,
  char* out
);

size_t write_rhdr(
  const std::vector<RecordFieldDescriptor>& fields,
  uint64_t record_count,
  char* out
);

size_t length_rdat_data(
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count
);

size_t length_rdat(
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count
);

size_t write_rdat_record(
  const std::vector<RecordFieldDescriptor>& fields,
  const std::vector<std::vector<uint8_t>>& record,
  char* out
);

size_t write_rdat_data(
  const RecordData& rdat,
  char* out
);

size_t write_rdat(
  const RecordData& rdat,
  char* out
);

size_t write_rdat(
  const std::vector<RecordFieldDescriptor>& fields,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out
);

size_t length_ftoc_data(size_t chunk_count);

size_t length_ftoc(size_t chunk_count);

size_t write_ftoc_data(
  const TableOfContents& toc,
  char* out
);

size_t write_ftoc(
  const TableOfContents& toc,
  char* out
);

size_t length_fend_data();

size_t length_fend();

size_t write_fend_data(char*);

size_t write_fend(char* out);
