#include "cpp20.h"
#include "hasher/common.h"
#include "hashset/hset_decoder_chunks.h"

#include <catch2/catch_test_macros.hpp>

#include <ostream>
#include <utility>

// C++20: #include <bit>

template <typename L, typename R>
std::ostream& operator<<(std::ostream& out, const std::pair<L,R>& p) {
  return out << '{' << p.first << ',' << p.second << '}';
}

TEST_CASE("decode_chunk") {
  const uint8_t in[] = {
    // chunk type
    'A', 'B', 'C', 'D',
    // chunk data length
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // chunk data
    '1', '2', '3', '4'
  };

  const uint8_t* beg = std::begin(in);
  const uint8_t* end = std::end(in);
  const uint8_t* cur = beg;

  const Chunk exp{0x41424344, beg + 12, beg + 16};

  CHECK(decode_chunk(beg, cur, end) == exp);
  CHECK(cur == end);
}

TEST_CASE("check_data_length_good") {
  const Chunk ch{
    0x41424344,
    reinterpret_cast<const uint8_t*>(0),
    reinterpret_cast<const uint8_t*>(100)
  };
  CHECK_NOTHROW(check_data_length(ch, 100));
}

TEST_CASE("check_data_length_bad") {
  const Chunk ch{
    0x41424344,
    reinterpret_cast<const uint8_t*>(0),
    reinterpret_cast<const uint8_t*>(100)
  };
  CHECK_THROWS(check_data_length(ch, 99));
}

TEST_CASE("parse_ftoc") {
  const uint8_t buf[] = {
    // entries
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'F', 'H', 'D', 'R',
    0x64, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'H', 'H', 0x00, 0x01,
    0x41, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'H', 'I', 'N', 'T',
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'H', 'D', 'A', 'T',
    0xA0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 'R', 'I', 'D', 'X',
    0xB0, 0xAD, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 'R', 'H', 'D', 'R',
    0xC0, 0xD4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 'R', 'D', 'A', 'T',
    0xD0, 0xFB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 'F', 'T', 'O', 'C'
  };

  const Chunk ch{Chunk::Type::FTOC, std::begin(buf), std::end(buf)};

  const TableOfContents exp{
    {
      { 8, Chunk::Type::FHDR },
      { 356, Chunk::Type::HHDR | 0x0001 },
      { 1089, Chunk::Type::HINT },
      { 4096, Chunk::Type::HDAT },
      { 100000, Chunk::Type::RIDX },
      { 110000, Chunk::Type::RHDR },
      { 120000, Chunk::Type::RDAT },
      { 130000, Chunk::Type::FTOC }
    }
  };

  CHECK(parse_ftoc(ch) == exp);
}

TEST_CASE("parse_fhdr") {
  const uint8_t buf[] = {
    // version
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hashset name length
    0x04, 0x00,
    // hashset name
    'n', 'a', 'm', 'e',
    // hashset timestamp length
    0x14, 0x00,
    // hashset timestamp
    '2', '0', '2', '2', '-', '1', '0', '-', '2', '6', 'T', '1', '8', ':', '1', '3', ':', '0', '7', 'Z',
    // hashset description length
    0x04, 0x00,
    // hashset description
    'd', 'e', 's', 'c',
  };

  const Chunk ch{Chunk::Type::FHDR, std::begin(buf), std::end(buf)};

  const FileHeader exp{
    2,
    "name",
    "2022-10-26T18:13:07Z",
    "desc",
    {}
  };

  CHECK(parse_fhdr(ch) == exp);
}

TEST_CASE("parse_hhdr") {
  const uint8_t buf[] = {
    // hash type name length
    0x05, 0x00,
    // hash type name
    'S', 'H', 'A', '-', '1',
    // hash length
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash count
    0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00
  };

  const uint32_t htype = bit_width(static_cast<uint32_t>(SFHASH_SHA_1)) - 1;

  const Chunk ch{Chunk::Type::HHDR | htype, std::begin(buf), std::end(buf)};

  const HashsetHeader exp{
    SFHASH_SHA_1,
    "SHA-1",
    20,
    4886718345
  };

  CHECK(parse_hhdr(ch) == exp);
}

TEST_CASE("parse_filter") {
  const uint8_t buf[] = {
    // filter type
    0x34, 0x12,
    // data!
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };

  const Chunk ch{Chunk::Type::FLTR, std::begin(buf), std::end(buf)};

  const HashsetFilter exp{ 0x1234, std::begin(buf) + 2, std::end(buf) };

  CHECK(parse_filter(ch) == exp);
}

TEST_CASE("parse_hint") {
  const uint8_t buf[] = {
    // hint type
    0x12, 0x34,
    // data!
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };

  const Chunk ch{Chunk::Type::HINT, std::begin(buf), std::end(buf)};

  const HashsetHint exp{ 0x1234, std::begin(buf) + 2, std::end(buf) };

  CHECK(parse_hint(ch) == exp);
}

TEST_CASE("parse_hdat") {
  uint8_t buf[] = {
    // data!
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };

  const Chunk ch{Chunk::Type::HDAT, std::begin(buf), std::end(buf)};

  const ConstHashsetData exp{ std::begin(buf), std::end(buf) };

  CHECK(parse_hdat(ch) == exp);
}

TEST_CASE("parse_ridx") {
  uint8_t buf[] = {
    // indices
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  const Chunk ch{Chunk::Type::RIDX, std::begin(buf), std::end(buf)};

  const ConstRecordIndex exp{ std::begin(buf), std::end(buf) };

  CHECK(parse_ridx(ch) == exp);
}

TEST_CASE("parse_rhdr") {
  const uint8_t buf[] = {
    // record length
    0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // record count
    0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00,
    //
    // field descriptor 0
    //
    // hash type
    0x00, 0x00,
    // hash type name length
    0x03, 0x00,
    // hash type name
    'M', 'D', '5',
    // hash length
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //
    // field descriptor 1
    //
    // hash type
    0x01, 0x00,
    // hash type name length
    0x05, 0x00,
    // hash type name
    'S', 'H', 'A', '-', '1',
    // hash length
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  const Chunk ch{Chunk::Type::RHDR, std::begin(buf), std::end(buf)};

  const RecordHeader exp{
    38,
    5649426,
    {
      { SFHASH_MD5, "MD5", 16 },
      { SFHASH_SHA_1, "SHA-1", 20 }
    }
  };

  CHECK(parse_rhdr(ch) == exp);
}

TEST_CASE("parse_rdat") {
  uint8_t buf[] = {
    // data!
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };

  const Chunk ch{Chunk::Type::RDAT, std::begin(buf), std::end(buf)};

  const ConstRecordData exp{ std::begin(buf), std::end(buf) };

  CHECK(parse_rdat(ch) == exp);
}
