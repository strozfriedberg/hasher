#pragma once

#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "hashset/lookupstrategy.h"

struct FileHeader {
  uint64_t version;
  std::string_view hashset_name;
  std::string_view hashset_time;
  std::string_view hashset_desc;

  bool operator==(const FileHeader&) const = default;
};

std::ostream& operator<<(std::ostream& out, const FileHeader& fhdr);

struct HashsetHeader {
  uint32_t hash_type;
  std::string_view hash_name;
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
  const void* beg;
  const void* end;

  bool operator==(const HashsetData&) const = default;
};

std::ostream& operator<<(std::ostream& out, const HashsetData& hdat);

struct RecordIndex {
  const void* beg;
  const void* end;

  bool operator==(const RecordIndex&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordIndex& ridx);

struct RecordFieldDescriptor {
  uint16_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;

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
  const void* beg;
  const void* end;

  bool operator==(const RecordData&) const = default;
};

std::ostream& operator<<(std::ostream& out, const RecordData& rdat);

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
  const uint8_t* dbeg;
  const uint8_t* dend;

  bool operator==(const Chunk&) const = default;
};

Chunk decode_chunk(const uint8_t* beg, const uint8_t*& cur, const uint8_t* end);

void check_data_length(const Chunk& ch, uint64_t exp_len);

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

std::pair<State::Type, FileHeader> parse_fhdr(const Chunk& ch);

std::pair<State::Type, HashsetHeader> parse_hhdr(const Chunk& ch);

std::pair<State::Type, HashsetHint> parse_hint(const Chunk& ch);

std::pair<State::Type, HashsetData> parse_hdat(const Chunk& ch);

std::pair<State::Type, RecordIndex> parse_ridx(const Chunk& ch);

std::pair<State::Type, RecordHeader> parse_rhdr(const Chunk& ch);

std::pair<State::Type, RecordData> parse_rdat(const Chunk& ch);

std::string printable_chunk_type(uint32_t type);

Holder decode_hset(const uint8_t* beg, const uint8_t* end);
