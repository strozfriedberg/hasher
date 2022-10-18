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
  BLOCK = 3,
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

Holder decode_hset(const char* beg, const char* end);
