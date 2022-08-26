#pragma once

#include <cstdint>
#include <string_view>
#include <variant>
#include <vector>
#include <utility>

struct FileHeader {
  uint64_t version;
  std::string_view hashset_name;
  std::string_view hashset_time;
  std::string_view hashset_desc;
};

struct HashsetHeader {
  uint64_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;
  uint64_t hash_count;
};

struct HashsetData {
  const void* beg;
  const void* end;
};

struct SizesetData {
  const void* beg;
  const void* end;
};

struct RecordHashFieldDescriptor {
  uint64_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;
};

struct RecordSizeFieldDescriptor {
};

struct RecordHeader {
  uint64_t record_length;
  uint64_t record_count;
  std::vector<std::variant<RecordHashFieldDescriptor, RecordSizeFieldDescriptor>> fields;
};

struct RecordData {
  const void* beg;
  const void* end;
};

struct Holder {
  FileHeader fhdr;
  std::vector<std::pair<HashsetHeader, HashsetData>> hsets;
  std::vector<std::pair<RecordHeader, RecordData>> recs;
  SizesetData sdat;
};

Holder read_chunks(const char* beg, const char* end);
