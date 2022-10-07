#include "hset_decoder.h"

#include "hex.h"
#include "util.h"
#include "hashset/basic_ls.h"
#include "hashset/lookupstrategy.h"
#include "hashset/util.h"

#include <algorithm>
#include <exception>
#include <map>
#include <ostream>

#include <iostream>

#include <boost/endian/conversion.hpp>

template <class T>
T read_pstring(const char* beg, const char*& i, const char* end) {
  const size_t len = read_le<uint16_t>(beg, i, end);
  THROW_IF(i + len > end, "out of data reading string at " << (i - beg));
  const char* sbeg = i;
  i += len;
  return T(sbeg, len);
}

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
  const char* dbeg;
  const char* dend;
};

std::string printable_chunk_type(uint32_t type) {
  const uint32_t t = boost::endian::native_to_big(type);
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

Chunk decode_chunk(const char* beg, const char*& cur, const char* end) {
  const uint32_t type = read_be<uint32_t>(beg, cur, end);
  const uint64_t len = read_le<uint64_t>(beg, cur, end);
  const char* dbeg = cur;

  cur = dbeg + len + 32;  // 32 is the length of the trailing hash

  return Chunk{ type, dbeg, dbeg + len };
}

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

State::Type parse_fhdr(const Chunk& ch, Holder& h) {
  // INIT -> FHDR

  const char* cur = ch.dbeg;
  h.fhdr.version = read_le<uint64_t>(ch.dbeg, cur, ch.dend);
  h.fhdr.hashset_name = read_pstring<std::string_view>(ch.dbeg, cur, ch.dend);
  h.fhdr.hashset_time = read_pstring<std::string_view>(ch.dbeg, cur, ch.dend);
  h.fhdr.hashset_desc = read_pstring<std::string_view>(ch.dbeg, cur, ch.dend);

  std::cerr << h.fhdr << "\n\n";

  return State::SBRK;
}

State::Type parse_hhdr(const Chunk& ch, Holder& h) {
  // section break -> HHDR

  const char* cur = ch.dbeg;

  h.hsets.emplace_back(
    HashsetHeader{
      static_cast<uint16_t>(ch.type & 0x0000FFFF),
      read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend)
    },
    HashsetHint(),
    HashsetData(),
    nullptr,
    RecordIndex()
  );

  std::cerr << std::get<HashsetHeader>(h.hsets.back()) << "\n\n";

  return State::HHDR;
}

State::Type parse_rhdr(const Chunk& ch, Holder& h) {
  // section break -> RHDR

  const char* cur = ch.dbeg;

  h.rhdr.record_length = read_le<uint64_t>(ch.dbeg, cur, ch.dend);
  h.rhdr.record_count = read_le<uint64_t>(ch.dbeg, cur, ch.dend);

  while (cur < ch.dend) {
    h.rhdr.fields.emplace_back(
      RecordFieldDescriptor{
        read_le<uint16_t>(ch.dbeg, cur, ch.dend),
        read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
        read_le<uint64_t>(ch.dbeg, cur, ch.dend)
      }
    );
  }

  std::cerr << h.rhdr << "\n\n";

  return State::RHDR;
}

State::Type parse_ftoc(const Chunk& ch, Holder& h) {
  // section break -> DONE

  // Nothing to do here, as we've already read the FTOC to drive parsing

  std::cerr << ch << "\n\n";

  return State::DONE;
}

template <size_t HashLength>
struct Make_BLS {
  template <class... Args>
  LookupStrategy* operator()(Args&&... args) {
    return new BasicLookupStrategy<HashLength>(std::forward<Args>(args)...);
  }
};

std::unique_ptr<LookupStrategy> make_lookup_strategy(
  const HashsetHeader& hsh,
  const HashsetHint& hnt,
  const HashsetData& hsd)
{
  switch (hnt.hint_type) {
  case HintType::RADIUS:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  case HintType::RANGE:
    return std::unique_ptr<LookupStrategy>(

      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  case HintType::BLOCK:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  case HintType::BLOCK_LINEAR:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  default:
    return std::unique_ptr<LookupStrategy>(
      hashset_dispatcher<Make_BLS>(
        hsh.hash_length, hsd.beg, hsd.end
      )
    );
  }
}

State::Type parse_hint(const Chunk& ch, Holder& h) {
  // HHDR -> HINT

  auto& [hsh, hnt, hsd, ls, _] = h.hsets.back();

  const char* cur = ch.dbeg;

  hnt.hint_type = read_le<uint16_t>(ch.dbeg, cur, ch.dend);

// TODO: check for recognized type?

  hnt.beg = cur;
  hnt.end = ch.dend;

  ls = make_lookup_strategy(hsh, hnt, hsd);

  std::cerr << hnt << "\n\n";

  return State::HINT;
}

State::Type parse_ridx(const Chunk& ch, Holder& h) {
  // HDAT -> RIDX;

  auto& hset = h.hsets.back();

  const uint64_t exp_ridx_data = std::get<HashsetHeader>(hset).hash_count * sizeof(uint64_t);

  THROW_IF(
    static_cast<uint64_t>(ch.dend - ch.dbeg) != exp_ridx_data,
    "expected " << exp_ridx_data << "bytes in RIDX, found "
                << (ch.dend - ch.dbeg)
  );

  std::get<RecordIndex>(hset).beg = ch.dbeg;
  std::get<RecordIndex>(hset).end = ch.dend;

  std::cerr << std::get<RecordIndex>(hset) << "\n\n";

  return State::SBRK;
}

State::Type parse_hdat(const Chunk& ch, Holder& h) {
  auto& hset = h.hsets.back();

  const uint64_t exp_hash_data = std::get<HashsetHeader>(hset).hash_count * std::get<HashsetHeader>(hset).hash_length;

  THROW_IF(
    static_cast<uint64_t>(ch.dend - ch.dbeg) != exp_hash_data,
    "expected " << exp_hash_data << "bytes in HDAT, found "
                << (ch.dend - ch.dbeg)
  );

  std::get<HashsetData>(hset).beg = ch.dbeg;
  std::get<HashsetData>(hset).end = ch.dend;

  std::cerr << std::get<HashsetData>(hset) << "\n\n";

  return State::HDAT;
}

State::Type parse_rdat(const Chunk& ch, Holder& h) {
  // RHDR -> RDAT;

  h.rdat.beg = ch.dbeg;
  h.rdat.end = ch.dend;

  std::cerr << h.rdat << "\n\n";

  return State::SBRK;
}

constexpr char MAGIC[] = {'S', 'e', 't', 'O', 'H', 'a', 's', 'h'};

void check_magic(const char*& i, const char* end) {
  // read magic
  THROW_IF(i + sizeof(MAGIC) > end, "out of data reading magic");
  THROW_IF(std::memcmp(i, MAGIC, sizeof(MAGIC)), "bad magic");
  i += sizeof(MAGIC);
}

// TODO: add validation flag

class UnexpectedChunkType: public std::exception {
};

class ChunkIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = Chunk;
  using pointer = const value_type*;
  using reference = const value_type&;
  using difference_type = std::ptrdiff_t;

  ChunkIterator(const char* beg, const char* end):
    beg(beg), cur(beg), end(end)
  {
    if (beg != end) {
      ++(*this);
    }
  }

  ChunkIterator(const char* end): ChunkIterator(end, end) {}

  reference operator*() const noexcept {
    return ch;
  }

  pointer operator->() const noexcept {
    return &ch;
  }

  ChunkIterator& operator++() {
    if (cur < end) {

      ch = decode_chunk(beg, cur, end);
    }
    return *this;
  }

  ChunkIterator operator++(int) {
    ChunkIterator itr{*this};
    ++(*this);
    return itr;
  }

  friend bool operator==(const ChunkIterator& a, const ChunkIterator& b) noexcept;
  friend bool operator!=(const ChunkIterator& a, const ChunkIterator& b) noexcept;

private:
  const char* beg;
  const char* cur;
  const char* end;

  Chunk ch;
};

bool operator==(const ChunkIterator& a, const ChunkIterator& b) noexcept {
  return a.cur == b.cur;
}

bool operator!=(const ChunkIterator& a, const ChunkIterator& b) noexcept {
  return a.cur != b.cur;
}

class TOCIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = Chunk;
  using pointer = const value_type*;
  using reference = const value_type&;
  using difference_type = std::ptrdiff_t;

  TOCIterator(const char* beg, const char* toc_cur, const char* toc_end, const char* end):
    beg(beg), toc_cur(toc_cur), toc_end(toc_end), end(end)
  {
    if (toc_cur < toc_end) {
      ++(*this);
    }
  }

  TOCIterator(const char* toc_end):
    TOCIterator(toc_end, toc_end, toc_end, toc_end) {}

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
    return *this;
  }

  TOCIterator operator++(int) {
    TOCIterator itr{*this};
    ++(*this);
    return itr;
  }

  friend bool operator==(const TOCIterator& a, const TOCIterator& b) noexcept;
  friend bool operator!=(const TOCIterator& a, const TOCIterator& b) noexcept;

private:
  void advance_chunk() {
    const uint64_t ch_off = read_le<uint64_t>(beg, toc_cur, toc_end);
    const uint32_t ch_type = read_be<uint32_t>(beg, toc_cur, toc_end);

    const char* cur = beg + ch_off;
    ch = decode_chunk(beg, cur, end);

    THROW_IF(
      ch_type != ch.type,
      "expected " << printable_chunk_type(ch_type) << ", "
      "found " << printable_chunk_type(ch.type)
    );
  }

  const char* beg;
  const char* toc_cur;
  const char* toc_end;
  const char* end;

  Chunk ch;
};

bool operator==(const TOCIterator& a, const TOCIterator& b) noexcept {
  return a.toc_cur == b.toc_cur;
}

bool operator!=(const TOCIterator& a, const TOCIterator& b) noexcept {
  return a.toc_cur != b.toc_cur;
}

Holder parse_hset(const char* beg, const char* end) {
  // check magic
  const char* cur = beg;
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
          state = parse_fhdr(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::SBRK:
        if ((ch->type & 0xFFFF0000) == Chunk::HHDR) {
          state = parse_hhdr(*ch++, h);
        }
        else if (ch->type == Chunk::RHDR) {
          state = parse_rhdr(*ch++, h);
        }
        else if (ch->type == Chunk::FTOC) {
          state = parse_ftoc(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::HHDR:
        switch (ch->type) {
        case Chunk::HINT:
          state = parse_hint(*ch++, h);
          break;
        case Chunk::HDAT:
          state = parse_hdat(*ch++, h);
          break;
        default:
          throw UnexpectedChunkType();
        }
        break;

      case State::HINT:
        if (ch->type == Chunk::HDAT) {
          state = parse_hdat(*ch++, h);
        }
        else {
          throw UnexpectedChunkType();
        }
        break;

      case State::HDAT:
        if (ch->type == Chunk::RIDX) {
          state = parse_ridx(*ch++, h);
        }
        else {
          state = State::SBRK;
        }
        break;

      case State::RHDR:
        if (ch->type == Chunk::RDAT) {
          state = parse_rdat(*ch++, h);
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
