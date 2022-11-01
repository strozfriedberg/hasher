#pragma once

#include <cstdint>
#include <exception>
#include <iosfwd>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "throw.h"
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

class TOCIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = Chunk;
  using pointer = const value_type*;
  using reference = const value_type&;
  using difference_type = std::ptrdiff_t;

  TOCIterator(
    const uint8_t* beg,
    const uint8_t* toc_cur,
    const uint8_t* toc_end,
    const uint8_t* end
  ):
    beg(beg), toc_cur(toc_cur), toc_end(toc_end), end(end)
  {
    if (toc_cur < toc_end) {
      ++(*this);
    }
  }

  TOCIterator():
    beg(nullptr), toc_cur(nullptr), toc_end(nullptr), end(nullptr) {}

  reference operator*() const noexcept {
    return ch;
  }

  pointer operator->() const noexcept {
    return &ch;
  }

  TOCIterator& operator++() {
    if (toc_cur < toc_end) {
      advance_chunk();
    }
    else {
      // this is the end
      toc_cur = toc_end = nullptr;
    }
    return *this;
  }

  TOCIterator operator++(int) {
    TOCIterator itr{*this};
    ++(*this);
    return itr;
  }

  bool operator==(const TOCIterator& other) const noexcept {
    return toc_cur == other.toc_cur;
  }

  bool operator!=(const TOCIterator&) const noexcept = default;

private:
  void advance_chunk();

  const uint8_t* beg;
  const uint8_t* toc_cur;
  const uint8_t* toc_end;
  const uint8_t* end;

  Chunk ch;
};

State::Type handle_fhdr(const Chunk& ch, Holder& h);

State::Type handle_hhdr(const Chunk& ch, Holder& h);

State::Type handle_rhdr(const Chunk& ch, Holder& h);

State::Type handle_ftoc(const Chunk& ch, Holder& h);

State::Type handle_hdat(const Chunk& ch, Holder& h);

State::Type handle_rdat(const Chunk& ch, Holder& h);

class UnexpectedChunkType: public std::exception {
};

template <class ChunkIterator>
Holder decode_hset(ChunkIterator ch, ChunkIterator ch_end) {
  Holder h;
  State::Type state = State::INIT;

  try {
    while (state != State::DONE) {
      THROW_IF(ch == ch_end, "exhausted FTOC expecting more data");

      switch (state) {
      case State::INIT:
        if (ch->type == Chunk::FHDR) {
          state = handle_fhdr(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::SBRK:
        if ((ch->type & 0xFFFF0000) == Chunk::HHDR) {
          state = handle_hhdr(*ch++, h);
        }
        else if (ch->type == Chunk::RHDR) {
          state = handle_rhdr(*ch++, h);
        }
        else if (ch->type == Chunk::FTOC) {
          state = handle_ftoc(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::HHDR:
        switch (ch->type) {
        case Chunk::HINT:
          state = handle_hint(*ch++, h);
          break;
        default:
          throw UnexpectedChunkType();
        case Chunk::HDAT:
          // intentional fall-through to HINT state
          ;
        }

      case State::HINT:
        if (ch->type == Chunk::HDAT) {
          state = handle_hdat(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::HDAT:
        if (ch->type == Chunk::RIDX) {
          state = handle_ridx(*ch++, h);
        }
        else {
          state = State::SBRK;
        }
        break;

      case State::RHDR:
        if (ch->type == Chunk::RDAT) {
          state = handle_rdat(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;
      }
    }
  }
  catch (const UnexpectedChunkType&) {
    THROW("unexpected chunk type " << printable_chunk_type(ch->type));
  }

  return h;
}

Holder decode_hset(const uint8_t* beg, const uint8_t* end);
