#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <tuple>
#include <vector>

#include "hashset/lookupstrategy.h"

struct FileHeader {
  uint64_t version;
  std::string_view hashset_name;
  std::string_view hashset_time;
  std::string_view hashset_desc;

  bool operator==(const FileHeader&) const = default;
};

struct HashsetHeader {
  uint32_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;
  uint64_t hash_count;
};

struct HashsetHint {
  uint16_t hint_type;
  const void* beg;
  const void* end;
};

enum HintType {
  BASIC = 0,
  RADIUS = 1,
  RANGE = 2,
  BLOCK = 'b',
  BLOCK_LINEAR = 4
};

struct HashsetData {
  const void* beg;
  const void* end;
};

struct RecordIndex {
  const void* beg;
  const void* end;
};

struct RecordFieldDescriptor {
  uint16_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;
};

struct RecordHeader {
  uint64_t record_length;
  uint64_t record_count;
  std::vector<RecordFieldDescriptor> fields;
};

struct RecordData {
  const void* beg;
  const void* end;
};

struct Holder {
  FileHeader fhdr;
  std::vector<
    std::tuple<
      HashsetHeader,
      HashsetHint,
      HashsetData,
      std::unique_ptr<LookupStrategy>,
      RecordIndex
    >
  > hsets;
  RecordHeader rhdr;
  RecordData rdat;
};

struct Chunk {
  enum Type {
    FHDR = 0x46484452,
    FTOC = 0x46544F43,
    HDAT = 0x48444154,
    HHDR = 0x48480000,
    HINT = 0x48494E54,
    RIDX = 0x52494458,
    RHDR = 0x52484452,
    RDAT = 0x52444154
  };

  uint32_t type;
  const char* dbeg;
  const char* dend;

  bool operator==(const Chunk&) const = default;
};

Chunk decode_chunk(const char* beg, const char*& cur, const char* end);

struct State {
  enum Type {
    INIT,
    SBRK, // section break
    HHDR,
    HINT,
    HDAT,
    RHDR,
    DONE
  };
};

Holder decode_hset(const char* beg, const char* end);
