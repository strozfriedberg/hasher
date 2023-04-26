#include "hashset/hset_decoder_chunks.h"

#include "throw.h"
#include "rwutil.h"

Chunk decode_chunk(const uint8_t* beg, const uint8_t*& cur, const uint8_t* end) {
  const uint32_t type = read_be<uint32_t>(beg, cur, end);
  const uint64_t len = read_le<uint64_t>(beg, cur, end);
  const uint8_t* dbeg = cur;

  cur = dbeg + len;

  return Chunk{ type, dbeg, dbeg + len };
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

FileHeader parse_fhdr(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;
  return {
    read_le<uint64_t>(ch.dbeg, cur, ch.dend),
    read_pstring<std::string>(ch.dbeg, cur, ch.dend),
    read_pstring<std::string>(ch.dbeg, cur, ch.dend),
    read_pstring<std::string>(ch.dbeg, cur, ch.dend),
    {}
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

HashsetFilter parse_filter(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;
  return {
    read_le<uint16_t>(ch.dbeg, cur, ch.dend),
    cur,
    ch.dend
  };
}

HashsetHint parse_hint(const Chunk& ch) {
  const uint8_t* cur = ch.dbeg;
  return {
    read_be<uint16_t>(ch.dbeg, cur, ch.dend),
    cur,
    ch.dend
  };
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
