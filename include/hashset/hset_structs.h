#pragma once

#include <array>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <utility>
#include <vector>

struct TableOfContents {
  std::vector<std::pair<uint64_t, uint32_t>> entries;

  bool operator==(const TableOfContents&) const = default;
};

std::ostream& operator<<(std::ostream& out, const TableOfContents& ftoc);

struct FileHeader {
  uint64_t version;
  std::string name;
  std::string time;
  std::string desc;
  std::array<uint8_t, 32> sha2_256;

  bool operator==(const FileHeader&) const = default;
};

std::ostream& operator<<(std::ostream& out, const FileHeader& fhdr);

struct HashsetHeader {
  uint32_t hash_type;
  std::string hash_name;
  uint64_t hash_length;
  uint64_t hash_count;

  bool operator==(const HashsetHeader&) const = default;
};

std::ostream& operator<<(std::ostream& out, const HashsetHeader& hhdr);

struct HashsetHint {
  uint16_t hint_type;
  const void* beg;
  const void* end;

  bool operator==(const HashsetHint&) const = default;
};

std::ostream& operator<<(std::ostream& out, const HashsetHint& hint);

enum HintType {
  BASIC = 0,
  RADIUS = 1,
  RANGE = 2,
  BLOCK = 'b',
  BLOCK_LINEAR = 4
};

struct HashsetData {
  uint8_t* beg;
  uint8_t* end;

  bool operator==(const HashsetData&) const = default;
};

std::ostream& operator<<(std::ostream& out, const HashsetData& hdat);

struct ConstHashsetData {
  const void* beg;
  const void* end;

  bool operator==(const ConstHashsetData&) const = default;
};

struct RecordIndex {
  void* beg;
  void* end;

  bool operator==(const RecordIndex&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordIndex& ridx);

struct ConstRecordIndex {
  const void* beg;
  const void* end;

  bool operator==(const ConstRecordIndex&) const = default;
};

struct RecordFieldDescriptor {
  uint32_t type;
  std::string name;
  uint64_t length;

  bool operator==(const RecordFieldDescriptor&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordFieldDescriptor& rfd);

struct RecordHeader {
  uint64_t record_length;
  uint64_t record_count;
  std::vector<RecordFieldDescriptor> fields;

  bool operator==(const RecordHeader&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordHeader& rhdr);

struct RecordData {
  uint8_t* beg;
  uint8_t* end;

  bool operator==(const RecordData&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordData& rdat);

struct ConstRecordData {
  const void* beg;
  const void* end;

  bool operator==(const ConstRecordData&) const = default;
};

std::ostream& operator<<(std::ostream& out, const ConstRecordData& rdat);

struct Chunk {
  enum Type {
    FTOC = 0x46544F43,
    FHDR = 0x46484452,
    RHDR = 0x52484452,
    RDAT = 0x52444154,
    HHDR = 0x48480000,
    HDAT = 0x48444154,
    HINT = 0x48494E54,
    RIDX = 0x52494458,
    FEND = 0x46454E44
  };

  uint32_t type;
  const uint8_t* dbeg;
  const uint8_t* dend;

  bool operator==(const Chunk&) const = default;
};

std::string printable_chunk_type(uint32_t type);
