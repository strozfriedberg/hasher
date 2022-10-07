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
  uint16_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;
  uint64_t hash_count;
};

struct HashsetHint {
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
      HashsetData,
      std::unique_ptr<LookupStrategy>,
      RecordIndex
    >
  > hsets;
  RecordHeader rhdr;
  RecordData rdat;
};

Holder parse_hset(const char* beg, const char* end);
