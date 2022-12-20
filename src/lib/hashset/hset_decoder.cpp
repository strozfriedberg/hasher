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
#include <iomanip>
#include <ostream>
#include <string_view>

#include <iostream>

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
  const auto [ch_off, ch_type] = *toc_cur++;

  const uint8_t* cur = beg + ch_off;
  ch = decode_chunk(beg, cur, end);

  THROW_IF(
    ch_type != ch.type,
    "expected " << printable_chunk_type(ch_type) << ", "
    "found " << printable_chunk_type(ch.type)
  );
}

FileHeader parse_fhdr(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;
  return {
    read_le<uint64_t>(ch.dbeg, cur, ch.dend),
    read_pstring<std::string>(ch.dbeg, cur, ch.dend),
    read_pstring<std::string>(ch.dbeg, cur, ch.dend),
    read_pstring<std::string>(ch.dbeg, cur, ch.dend)
  };
}

HashsetHeader parse_hhdr(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;
  return {
    1u << (ch.type & 0x0000FFFF),
    read_pstring<std::string>(ch.dbeg, cur, ch.dend),
    read_le<uint64_t>(ch.dbeg, cur, ch.dend),
    read_le<uint64_t>(ch.dbeg, cur, ch.dend)
  };
}

RecordHeader parse_rhdr(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;

  RecordHeader rhdr{
    read_le<uint64_t>(ch.dbeg, cur, ch.dend),
    read_le<uint64_t>(ch.dbeg, cur, ch.dend),
    {}
  };

  while (cur < ch.dend) {
    rhdr.fields.emplace_back(
      RecordFieldDescriptor{
        1u << read_le<uint16_t>(ch.dbeg, cur, ch.dend),
        read_pstring<std::string>(ch.dbeg, cur, ch.dend),
        read_le<uint64_t>(ch.dbeg, cur, ch.dend)
      }
    );
  }

  return rhdr;
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
  const ConstHashsetData& hsd)
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

HashsetHint parse_hint(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;
  return {
    read_be<uint16_t>(ch.dbeg, cur, ch.dend),
    cur,
    ch.dend
  };
}

void check_data_length(const Chunk& ch, uint64_t exp_len) {
  const uint64_t act_len = static_cast<const uint8_t*>(ch.dend) - static_cast<const uint8_t*>(ch.dbeg);
  THROW_IF(
    act_len != exp_len,
    "expected " << exp_len << " bytes in "
                << printable_chunk_type(ch.type)
                << ", found " << act_len
  );
}

ConstRecordIndex parse_ridx(const Chunk& ch) {
  return { ch.dbeg, ch.dend };
}

ConstHashsetData parse_hdat(const Chunk& ch) {
  return { ch.dbeg, ch.dend };
}

ConstRecordData parse_rdat(const Chunk& ch) {
  return { ch.dbeg, ch.dend };
}

TableOfContents parse_ftoc(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;

  TableOfContents toc;

  while (cur < ch.dend) {
    const uint64_t pos = read_le<uint64_t>(ch.dbeg, cur, ch.dend);
    const uint32_t type = read_be<uint32_t>(ch.dbeg, cur, ch.dend);
    toc.entries.emplace_back(pos, type);
  }

  return toc;
}

constexpr char MAGIC[] = {'S', 'e', 't', 'O', 'H', 'a', 's', 'h'};

void check_magic(const uint8_t*& i, const uint8_t* end) {
  // read magic
  THROW_IF(i + sizeof(MAGIC) > end, "out of data reading magic");
  THROW_IF(std::memcmp(i, MAGIC, sizeof(MAGIC)), "bad magic");
  i += sizeof(MAGIC);
}

State::Type handle_fhdr(const Chunk& ch, Holder& h) {
  // INIT -> FHDR
  h.fhdr = parse_fhdr(ch);
  return State::FHDR;
}

State::Type handle_hhdr(const Chunk& ch, Holder& h) {
  // section break -> HHDR
  h.hsets.emplace_back(
    parse_hhdr(ch),
    HashsetHint(),
    ConstHashsetData(),
    nullptr,
    ConstRecordIndex()
  );

  return State::HHDR;
}

State::Type handle_rhdr(const Chunk& ch, Holder& h) {
  h.rhdr = parse_rhdr(ch);
  return State::RHDR;
}

State::Type handle_ftoc(const Chunk&, Holder&) {
  // Nothing to do here, as we've already read the FTOC to drive parsing
  return State::FTOC;
}

State::Type handle_hint(const Chunk& ch, Holder& h) {
  auto& hset = h.hsets.back();
  auto& hnt = std::get<HashsetHint>(hset);

  hnt = parse_hint(ch);

  // TODO: check for recognized type?
  THROW_IF(
    hnt.hint_type != 0x6208,
    "bad hint type " << std::hex << std::setw(4) << std::setfill('0') << hnt.hint_type
  );

  return State::HINT;
}

State::Type handle_hdat(const Chunk& ch, Holder& h) {
  auto& hset = h.hsets.back();
  const auto& hhdr = std::get<HashsetHeader>(hset);
  auto& hdat = std::get<ConstHashsetData>(hset);

  check_data_length(ch, hhdr.hash_count * hhdr.hash_length);

  hdat = parse_hdat(ch);
  return State::HDAT;
}

State::Type handle_ridx(const Chunk& ch, Holder& h) {
  auto& hset = h.hsets.back();
  const auto& hhdr = std::get<HashsetHeader>(hset);
  auto& ridx = std::get<ConstRecordIndex>(hset);

  check_data_length(ch, hhdr.hash_count * sizeof(uint64_t));

  ridx = parse_ridx(ch);
  return State::SBRK;
}

State::Type handle_rdat(const Chunk& ch, Holder& h) {
  check_data_length(ch, h.rhdr.record_count * h.rhdr.record_length);
  h.rdat = parse_rdat(ch);
  return State::SBRK;
}

State::Type handle_fend(const Chunk&, Holder&) {
  return State::DONE;
}

TableOfContents read_ftoc_chunk(const uint8_t* beg, const uint8_t*& cur, const uint8_t* end) {
  // get the FTOC chunk
  const Chunk ch = decode_chunk(beg, cur, end);

  THROW_IF(
    ch.type != Chunk::FTOC,
    "expected FTOC, found " << printable_chunk_type(ch.type)
  );

  return parse_ftoc(ch);
}

// TODO: add validation flag

Holder decode_hset(const uint8_t* beg, const uint8_t* end) {
  const uint8_t* cur = beg;

  // check magic
  check_magic(cur, end);

  // read the FTOC chunk
  const TableOfContents toc = read_ftoc_chunk(beg, cur, end);

  // decode the chunks listed in the FTOC
  TOCIterator ch(toc, beg, end), ch_end;
  Holder h = decode_chunks(ch, ch_end);

  // install lookup strategies
  for (auto& [hsh, hnt, hsd, ls, _]: h.hsets) {
    ls = make_lookup_strategy(hsh, hnt, hsd);
  }

  return h;
}
