#pragma once

#include <exception>
#include <iterator>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "throw.h"
#include "hashset/hset_structs.h"
#include "hashset/lookupstrategy.h"

struct Holder {
  FileHeader fhdr;
  std::vector<
    std::tuple<
      HashsetHeader,
      HashsetHint,
      ConstHashsetData,
      std::unique_ptr<LookupStrategy>,
      ConstRecordIndex
    >
  > hsets;
  RecordHeader rhdr;
  ConstRecordData rdat;
};

Chunk decode_chunk(const uint8_t* beg, const uint8_t*& cur, const uint8_t* end);

void check_data_length(const Chunk& ch, uint64_t exp_len);

struct State {
  enum Type {
    INIT,
    FTOC,
    FHDR,
    RHDR,
    SBRK, // section break
    HHDR,
    HINT,
    HDAT,
    DONE
  };
};

TableOfContents parse_ftoc(const Chunk& ch);

FileHeader parse_fhdr(const Chunk& ch);

HashsetHeader parse_hhdr(const Chunk& ch);

HashsetHint parse_hint(const Chunk& ch);

ConstHashsetData parse_hdat(const Chunk& ch);

ConstRecordIndex parse_ridx(const Chunk& ch);

RecordHeader parse_rhdr(const Chunk& ch);

ConstRecordData parse_rdat(const Chunk& ch);

class TOCIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = Chunk;
  using pointer = const value_type*;
  using reference = const value_type&;
  using difference_type = std::ptrdiff_t;

  TOCIterator(
    const TableOfContents& toc,
    const uint8_t* beg,
    const uint8_t* end
  ):
    beg(beg), end(end),
    toc_cur(toc.entries.begin()), toc_end(toc.entries.end())
  {
    if (toc_cur != toc_end) {
      ++(*this);
    }
  }

  TOCIterator():
    beg(nullptr), end(nullptr),
    toc_cur(), toc_end() {}

  reference operator*() const noexcept {
    return ch;
  }

  pointer operator->() const noexcept {
    return &ch;
  }

  TOCIterator& operator++() {
    if (toc_cur != toc_end) {
      advance_chunk();
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

  const uint8_t* const beg;
  const uint8_t* const end;
  decltype(TableOfContents::entries)::const_iterator toc_cur;
  const decltype(TableOfContents::entries)::const_iterator toc_end;

  Chunk ch;
};

State::Type handle_fhdr(const Chunk& ch, Holder& h);

State::Type handle_hhdr(const Chunk& ch, Holder& h);

State::Type handle_rhdr(const Chunk& ch, Holder& h);

State::Type handle_ftoc(const Chunk& ch, Holder& h);

State::Type handle_hdat(const Chunk& ch, Holder& h);

State::Type handle_rdat(const Chunk& ch, Holder& h);

State::Type handle_fend(const Chunk& ch, Holder& h);

class UnexpectedChunkType: public std::exception {
};

template <class ChunkIterator>
Holder decode_chunks(ChunkIterator ch, ChunkIterator ch_end) {
  Holder h;
  State::Type state = State::INIT;

  try {
    while (state != State::DONE) {
      THROW_IF(ch == ch_end, "exhausted FTOC expecting more data");

      switch (state) {
      case State::INIT:
        if (ch->type == Chunk::FTOC) {
          state = handle_ftoc(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::FTOC:
        if (ch->type == Chunk::FHDR) {
          state = handle_fhdr(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::FHDR:
        if (ch->type == Chunk::RHDR) {
          state = handle_rhdr(*ch++, h);
        }
        else if ((ch->type & 0xFFFF0000) == Chunk::HHDR) {
          state = handle_hhdr(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
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

      case State::SBRK:
        if ((ch->type & 0xFFFF0000) == Chunk::HHDR) {
          state = handle_hhdr(*ch++, h);
        }
        else if (ch->type == Chunk::FEND) {
          state = handle_fend(*ch++, h);
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

      case State::DONE:
        // should not happen, loop will exit first
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
