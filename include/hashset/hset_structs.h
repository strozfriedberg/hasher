#pragma once

#include <array>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <utility>
#include <vector>

struct TableOfContents {
  std::vector<std::pair<uint64_t, uint32_t>> entries;

// C++20: bool operator==(const TableOfContents&) const = default;
  bool operator==(const TableOfContents& o) const {
    return entries == o.entries;
  }
};

std::ostream& operator<<(std::ostream& out, const TableOfContents& ftoc);

struct FileHeader {
  uint64_t version;
  std::string name;
  std::string time;
  std::string desc;
  std::array<uint8_t, 32> sha2_256;

// C++20: bool operator==(const FileHeader&) const = default;
  bool operator==(const FileHeader& o) const {
    return version == o.version &&
           name == o.name &&
           time == o.time &&
           desc == o.desc &&
           sha2_256 == o.sha2_256;
  }
};

std::ostream& operator<<(std::ostream& out, const FileHeader& fhdr);

struct HashsetHeader {
  uint32_t hash_type;
  std::string hash_name;
  uint64_t hash_length;
  uint64_t hash_count;

// C++20: bool operator==(const HashsetHeader&) const = default;
  bool operator==(const HashsetHeader& o) const {
    return hash_type == o.hash_type &&
           hash_name == o.hash_name &&
           hash_length == o.hash_length &&
           hash_count == o.hash_count;
  }
};

std::ostream& operator<<(std::ostream& out, const HashsetHeader& hhdr);

struct HashsetHint {
  uint16_t hint_type;
  const void* beg;
  const void* end;

// C++20: bool operator==(const HashsetHint&) const = default;
  bool operator==(const HashsetHint& o) const {
    return hint_type == o.hint_type &&
           beg == o.beg &&
           end == o.end;
  }
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

// C++20: bool operator==(const HashsetData&) const = default;
};

std::ostream& operator<<(std::ostream& out, const HashsetData& hdat);

struct ConstHashsetData {
  const void* beg;
  const void* end;

// C++20: bool operator==(const ConstHashsetData&) const = default;
  bool operator==(const ConstHashsetData& o) const {
    return beg == o.beg && end == o.end;
  }
};

struct RecordIndex {
  void* beg;
  void* end;

// C++20: bool operator==(const RecordIndex&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordIndex& ridx);

struct ConstRecordIndex {
  const void* beg;
  const void* end;

// C+20: bool operator==(const ConstRecordIndex&) const = default;
  bool operator==(const ConstRecordIndex& o) const {
    return beg == o.beg && end == o.end;
  }
};

struct RecordFieldDescriptor {
  /*
  * This is a workaround for clang <= 15. Once 16 is out
  * we should remove this #if.
  */
// C++20: #if defined __clang__ && __clang_major__ <= 15
  RecordFieldDescriptor(uint32_t type, std::string name, uint64_t length)
    : type(type), name(std::move(name)), length(length) {}
// C++20: #endif

  uint32_t type;
  std::string name;
  uint64_t length;

// C++20: bool operator==(const RecordFieldDescriptor&) const = default;
  bool operator==(const RecordFieldDescriptor& o) const {
    return type == o.type && name == o.name && length == o.length;
  }
};

std::ostream& operator<<(std::ostream& out, const RecordFieldDescriptor& rfd);

struct RecordHeader {
  uint64_t record_length;
  uint64_t record_count;
  std::vector<RecordFieldDescriptor> fields;

// C++20: bool operator==(const RecordHeader&) const = default;
  bool operator==(const RecordHeader& o) const {
    return record_length == o.record_length &&
           record_count == o.record_count &&
           fields == o.fields;
  }
};

std::ostream& operator<<(std::ostream& out, const RecordHeader& rhdr);

struct RecordData {
  uint8_t* beg;
  uint8_t* end;

// C++20: bool operator==(const RecordData&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordData& rdat);

struct ConstRecordData {
  const uint8_t* beg;
  const uint8_t* end;

// C++20: bool operator==(const ConstRecordData&) const = default;
  bool operator==(const ConstRecordData& o) const {
    return beg == o.beg && end == o.end;
  }
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

// C++20: bool operator==(const Chunk&) const = default;
  bool operator==(const Chunk& o) const {
    return type == o.type && dbeg == o.dbeg && dend == o.dend;
  }
};

std::string printable_chunk_type(uint32_t type);
