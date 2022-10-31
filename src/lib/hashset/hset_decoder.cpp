#include "hset_decoder.h"

#include "hex.h"
#include "hashset/basic_ls.h"
#include "hashset/block_ls.h"
#include "hashset/lookupstrategy.h"
#include "hashset/radius_ls.h"
#include "hashset/range_ls.h"
#include "hashset/util.h"
#include "rwutil.h"

#include <algorithm>
#include <exception>
#include <map>
#include <ostream>
#include <string_view>

#include <iostream>

std::ostream& operator<<(std::ostream& out, const FileHeader& fhdr) {
  return out << "FHDR\n"
             << ' ' << fhdr.version << '\n'
             << ' ' << fhdr.hashset_name << '\n'
             << ' ' << fhdr.hashset_time << '\n'
             << ' ' << fhdr.hashset_desc;
}

std::ostream& operator<<(std::ostream& out, const HashsetHeader& hhdr) {
  return out << "HHDR\n"
             << ' ' << hhdr.hash_type << '\n'
             << ' ' << hhdr.hash_name << '\n'
             << ' ' << hhdr.hash_length << '\n'
             << ' ' << hhdr.hash_count;
}

std::ostream& operator<<(std::ostream& out, const HashsetHint& hint) {
  return out << "HINT\n"
             << ' ' << hint.hint_type << '\n'
             << ' ' << hint.beg << '\n'
             << ' ' << hint.end;
}

std::ostream& operator<<(std::ostream& out, const HashsetData& hdat) {
  return out << "HDAT\n"
             << ' ' << hdat.beg << '\n'
             << ' ' << hdat.end;
}

std::ostream& operator<<(std::ostream& out, const RecordIndex& ridx) {
  return out << "RIDX\n"
             << ' ' << ridx.beg << '\n'
             << ' ' << ridx.end;
}

std::ostream& operator<<(std::ostream& out, const RecordFieldDescriptor& rfd) {
  return out << "RFD\n"
             << ' ' << rfd.hash_type << '\n'
             << ' ' << rfd.hash_name << '\n'
             << ' ' << rfd.hash_length;
}

std::ostream& operator<<(std::ostream& out, const RecordHeader& rhdr) {
  out << "RHDR\n"
      << ' ' << rhdr.record_length << '\n'
      << ' ' << rhdr.record_count << '\n';

  for (const auto& f: rhdr.fields) {
    out << f << '\n';
  }

  return out;
}

std::ostream& operator<<(std::ostream& out, const RecordData& rdat) {
  return out << "RDAT\n"
             << ' ' << rdat.beg << '\n'
             << ' ' << rdat.end;
}

std::string printable_chunk_type(uint32_t type) {
  const uint32_t t = to_be(type);
  const char* tt = reinterpret_cast<const char*>(&t);

  if (tt[0] == 'H' && tt[1] == 'H') {
    return "HH " + to_hex(tt + 2, tt + 4);
  }
  else {
    return std::string(tt, tt + 4);
  }
}

std::ostream& operator<<(std::ostream& out, const Chunk& ch) {
  return out << printable_chunk_type(ch.type)
             << " ["
             << static_cast<const void*>(ch.dbeg)
             << ','
             << static_cast<const void*>(ch.dend)
             << "]";
}

// TODO: optionally? check chunk hash

Chunk decode_chunk(const uint8_t* beg, const uint8_t*& cur, const uint8_t* end) {
  const uint32_t type = read_be<uint32_t>(beg, cur, end);
  const uint64_t len = read_le<uint64_t>(beg, cur, end);
  const uint8_t* dbeg = cur;

  cur = dbeg + len + 32;  // 32 is the length of the trailing hash

  return Chunk{ type, dbeg, dbeg + len };
}

void TOCIterator::advance_chunk() {
  const uint64_t ch_off = read_le<uint64_t>(beg, toc_cur, toc_end);
  const uint32_t ch_type = read_be<uint32_t>(beg, toc_cur, toc_end);

  const uint8_t* cur = beg + ch_off;
  ch = decode_chunk(beg, cur, end);

  THROW_IF(
    ch_type != ch.type,
    "expected " << printable_chunk_type(ch_type) << ", "
    "found " << printable_chunk_type(ch.type)
  );
}

std::pair<State::Type, FileHeader> parse_fhdr(const Chunk& ch) {
  // INIT -> FHDR
  const uint8_t* cur = ch.dbeg;
  return {
    State::SBRK,
    FileHeader{
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
      read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
      read_pstring<std::string_view>(ch.dbeg, cur, ch.dend)
    }
  }; 
}

std::pair<State::Type, HashsetHeader> parse_hhdr(const Chunk& ch) {
  // section break -> HHDR
  const uint8_t* cur = ch.dbeg;
  return {
    State::HHDR,
    HashsetHeader{
      1u << (ch.type & 0x0000FFFF),
      read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend)
    }
  };
}
 
std::pair<State::Type, RecordHeader> parse_rhdr(const Chunk& ch) {
  // section break -> RHDR

  const uint8_t* cur = ch.dbeg;

  RecordHeader rhdr{
    read_le<uint64_t>(ch.dbeg, cur, ch.dend),
    read_le<uint64_t>(ch.dbeg, cur, ch.dend),
    {}
  };

  while (cur < ch.dend) {
    rhdr.fields.emplace_back(
      RecordFieldDescriptor{
        read_le<uint16_t>(ch.dbeg, cur, ch.dend),
        read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
        read_le<uint64_t>(ch.dbeg, cur, ch.dend)
      }
    );
  }

  return {
    State::RHDR,
    rhdr
  };
}

State::Type parse_ftoc(const Chunk&) {
  // section break -> DONE

  // Nothing to do here, as we've already read the FTOC to drive parsing
  return State::DONE;
}

template <template <size_t> class Strategy, size_t HashLength>
struct MakeLookupStrategy {
  template <class... Args>
  LookupStrategy* operator()(Args&&... args) {
    return new Strategy<HashLength>(std::forward<Args>(args)...);
  }
};

template <size_t HashLength>
struct MakeBasicLookupStrategy: public MakeLookupStrategy<BasicLookupStrategy, HashLength> {};

template <size_t HashLength>
struct MakeRadiusLookupStrategy: public MakeLookupStrategy<RadiusLookupStrategy, HashLength> {};

template <size_t HashLength>
struct MakeRangeLookupStrategy: public MakeLookupStrategy<RangeLookupStrategy, HashLength> {};

template <size_t BlockBits>
std::array<std::pair<int64_t, int64_t>, (1 << BlockBits)> make_blocks(const HashsetHint& hnt) {
  std::array<std::pair<int64_t, int64_t>, (1 << BlockBits)> blocks;

  std::copy(
    static_cast<const std::pair<int64_t, int64_t>*>(hnt.beg),
    static_cast<const std::pair<int64_t, int64_t>*>(hnt.end),
    blocks.begin()
  );

  return blocks;
}

template <size_t BlockBits, size_t HashLength>
struct MakeBlockLookupStrategy {
  template <class... Args>
  LookupStrategy* operator()(Args&&... args) {
    return new BlockLookupStrategy<BlockBits, HashLength>(std::forward<Args>(args)...);
  }
};

// TODO: there must be a way to template this
template <size_t HashLength>
struct MakeBlockLookupStrategy1: public MakeBlockLookupStrategy<HashLength, 1> {};

template <size_t HashLength>
struct MakeBlockLookupStrategy2: public MakeBlockLookupStrategy<HashLength, 2> {};

template <size_t HashLength>
struct MakeBlockLookupStrategy3: public MakeBlockLookupStrategy<HashLength, 3> {};

template <size_t HashLength>
struct MakeBlockLookupStrategy4: public MakeBlockLookupStrategy<HashLength, 4> {};

template <size_t HashLength>
struct MakeBlockLookupStrategy5: public MakeBlockLookupStrategy<HashLength, 5> {};

template <size_t HashLength>
struct MakeBlockLookupStrategy6: public MakeBlockLookupStrategy<HashLength, 6> {};

template <size_t HashLength>
struct MakeBlockLookupStrategy7: public MakeBlockLookupStrategy<HashLength, 7> {};

template <size_t HashLength>
struct MakeBlockLookupStrategy8: public MakeBlockLookupStrategy<HashLength, 8> {};

std::unique_ptr<LookupStrategy> make_lookup_strategy(
  const HashsetHeader& hsh,
  const HashsetHint& hnt,
  const HashsetData& hsd)
{
  // TODO: check that hnt is long enough to hold data?

  if (hnt.hint_type == 0x6208) {
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<MakeBlockLookupStrategy8>(
        hsh.hash_length, hsd.beg, hsd.end,
        make_blocks<8>(hnt)
      )
    );
  }
  else {
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<MakeBasicLookupStrategy>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  }

/*
  switch (hnt.hint_type) {
  case HintType::RADIUS:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<MakeRadiusLookupStrategy>(
        hsh.hash_length, hsd.beg, hsd.end,
        *static_cast<const uint32_t*>(hnt.beg)
      )
    );
  case HintType::RANGE:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<MakeRangeLookupStrategy>(
        hsh.hash_length, hsd.beg, hsd.end,
        *static_cast<const int64_t*>(hnt.beg),
        *(static_cast<const int64_t*>(hnt.beg) + 1)
      )
    );
  case HintType::BLOCK:
    {
// TODO: bounds check
      const uint8_t bits = *static_cast<const uint8_t*>(hnt.beg);
      switch (bits) {
      case 1:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy1>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<1>(hnt)
          )
        );
      case 2:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy2>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<2>(hnt)
          )
        );
      case 3:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy3>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<3>(hnt)
          )
        );
      case 4:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy4>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<4>(hnt)
          )
        );
      case 5:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy5>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<5>(hnt)
          )
        );

      case 6:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy6>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<6>(hnt)
          )
        );
      case 7:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy7>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<7>(hnt)
          )
        );
      case 8:
        return std::unique_ptr<LookupStrategy>(
          hashset_dispatcher<MakeBlockLookupStrategy8>(
            hsh.hash_length, hsd.beg, hsd.end,
            make_blocks<8>(hnt)
          )
        );
      }
    }
  case HintType::BLOCK_LINEAR:
    // TODO
  default:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<MakeBasicLookupStrategy>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  }
*/
}

std::pair<State::Type, HashsetHint> parse_hint(const Chunk& ch) {
  // HHDR -> HINT
  const uint8_t* cur = ch.dbeg;
  return {
    State::HINT,
    {
      read_be<uint16_t>(ch.dbeg, cur, ch.dend),
      cur,
      ch.dend
    }
  };
}

template <State::Type state, class T>
std::pair<State::Type, T> parse_data_chunk(const Chunk& ch) {
  return {
    state,
    { ch.dbeg, ch.dend }
  };
}

void check_data_length(const Chunk& ch, uint64_t exp_len) {
  const uint64_t act_len = static_cast<const uint8_t*>(ch.dend) - static_cast<const uint8_t*>(ch.dbeg);
  THROW_IF(
    act_len != exp_len,
    "expected " << exp_len << "bytes in "
                << std::string_view(reinterpret_cast<const char*>(&ch.type), 4)
                << ", found " << act_len
  );
}

std::pair<State::Type, RecordIndex> parse_ridx(const Chunk& ch) {
  // HDAT -> RIDX;
  return parse_data_chunk<State::SBRK, RecordIndex>(ch);
}

std::pair<State::Type, HashsetData> parse_hdat(const Chunk& ch) {
  return parse_data_chunk<State::HDAT, HashsetData>(ch);
}

std::pair<State::Type, RecordData> parse_rdat(const Chunk& ch) {
  // RHDR -> RDAT;
  return parse_data_chunk<State::SBRK, RecordData>(ch);
}

constexpr char MAGIC[] = {'S', 'e', 't', 'O', 'H', 'a', 's', 'h'};

void check_magic(const uint8_t*& i, const uint8_t* end) {
  // read magic
  THROW_IF(i + sizeof(MAGIC) > end, "out of data reading magic");
  THROW_IF(std::memcmp(i, MAGIC, sizeof(MAGIC)), "bad magic");
  i += sizeof(MAGIC);
}

// TODO: add validation flag

class UnexpectedChunkType: public std::exception {
};

Holder decode_hset(const uint8_t* beg, const uint8_t* end) {
  // check magic
  const uint8_t* cur = beg;
  check_magic(cur, end);

  // read FTOC start offset from the last FTOC entry
  cur = end - 32 - 4 - 8; // end - SHA256 - chunk type - offset
  cur = beg + read_le<uint64_t>(beg, cur, end);

  // get the FTOC chunk
  const Chunk toc_ch = decode_chunk(beg, cur, end);

  THROW_IF(
    toc_ch.type != Chunk::FTOC,
    "expected FTOC, found " << printable_chunk_type(toc_ch.type)
  );

  TOCIterator ch(beg, toc_ch.dbeg, toc_ch.dend, end), ch_end(end);

  Holder h;
  State::Type state = State::INIT;

  try {
    while (state != State::DONE) {
      std::cerr << state << "\n\n";

      THROW_IF(ch == ch_end, "exhausted FTOC expecting more data");

      switch (state) {
      case State::INIT:
        if (ch->type == Chunk::FHDR) {
          std::tie(state, h.fhdr) = parse_fhdr(*ch++);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::SBRK:
        if ((ch->type & 0xFFFF0000) == Chunk::HHDR) {
          HashsetHeader hhdr;
          std::tie(state, hhdr) = parse_hhdr(*ch++);
          h.hsets.emplace_back(
            std::move(hhdr),
            HashsetHint(),
            HashsetData(),
            nullptr,
            RecordIndex()
          );
        }
        else if (ch->type == Chunk::RHDR) {
          std::tie(state, h.rhdr) = parse_rhdr(*ch++);
        }
        else if (ch->type == Chunk::FTOC) {
          state = parse_ftoc(*ch++);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::HHDR:
        switch (ch->type) {
        case Chunk::HINT:
          {
            auto& [hsh, hnt, hsd, ls, _] = h.hsets.back();

            std::tie(state, hnt) = parse_hint(*ch++);

            // TODO: check for recognized type?
            THROW_IF(
              hnt.hint_type != 0x6208,
              "bad hint type " << std::hex << std::setw(4) << std::setfill('0') << hnt.hint_type
            );

            ls = make_lookup_strategy(hsh, hnt, hsd);
          }
          break;
        default:
          throw UnexpectedChunkType();
        case Chunk::HDAT:
          // intentional fall-through to HINT state
          ;
        }

      case State::HINT:
        if (ch->type == Chunk::HDAT) {
          auto& hset = h.hsets.back();
          const auto& hhdr = std::get<HashsetHeader>(hset);
          auto& hdat = std::get<HashsetData>(hset);

          check_data_length(*ch, hhdr.hash_count * hhdr.hash_length);
          std::tie(state, hdat) = parse_hdat(*ch++);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::HDAT:
        if (ch->type == Chunk::RIDX) {
          auto& hset = h.hsets.back();
          const auto& hhdr = std::get<HashsetHeader>(hset);
          auto& ridx = std::get<RecordIndex>(hset);

          check_data_length(*ch, hhdr.hash_count * sizeof(uint64_t));
          std::tie(state, ridx) = parse_ridx(*ch++);
        }
        else {
          state = State::SBRK;
        }
        break;

      case State::RHDR:
        if (ch->type == Chunk::RDAT) {
          check_data_length(*ch, h.rhdr.record_count * h.rhdr.record_length);
          std::tie(state, h.rdat) = parse_rdat(*ch++);
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
