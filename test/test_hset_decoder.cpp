#include "hset_decoder.h"

#include "hasher/common.h"

#include "helper.h"

#include <cmath>

#include <catch2/catch_test_macros.hpp>

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
    '1', '2', '3', '4',
    // chunk hash
    0x03, 0xac, 0x67, 0x42, 0x16, 0xf3, 0xe1, 0x5c,
    0x76, 0x1e, 0xe1, 0xa5, 0xe2, 0x55, 0xf0, 0x67,
    0x95, 0x36, 0x23, 0xc8, 0xb3, 0x88, 0xb4, 0x45,
    0x9e, 0x13, 0xf9, 0x78, 0xd7, 0xc8, 0x46, 0xf4
  };

  const uint8_t* beg = in;
  const uint8_t* end = beg + sizeof(in);
  const uint8_t* cur = beg;

  const Chunk exp{0x41424344, beg + 12, beg + 16};

  CHECK(decode_chunk(beg, cur, end) == exp);
  CHECK(cur == end);
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

  const Chunk ch{Chunk::Type::FHDR, buf, buf + sizeof(buf)};

  const FileHeader exp{
    2,
    "name",
    "2022-10-26T18:13:07Z",
    "desc"
  };

  CHECK(parse_fhdr(ch) == std::make_pair(State::SBRK, exp));
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

  const uint32_t htype = static_cast<uint32_t>(std::floor(std::log2(static_cast<uint32_t>(SFHASH_SHA_1))));

  const Chunk ch{Chunk::Type::HHDR | htype, buf, buf + sizeof(buf)};

  const HashsetHeader exp{
    SFHASH_SHA_1,
    "SHA-1",
    20,
    4886718345
  };

  CHECK(parse_hhdr(ch) == std::make_pair(State::HHDR, exp));
}

/*
TEST_CASE("parse_hint") {
}

TEST_CASE("parse_hdat") {
  const uint8_t buf[] = {
    // hash data
    0x05, 0x00,
    // hash type name
    'S', 'H', 'A', '-', '1',
    // hash length
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash count
    0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00
  };

  const uint32_t htype = static_cast<uint32_t>(std::floor(std::log2(static_cast<uint32_t>(SFHASH_SHA_1))));

  const Chunk ch{Chunk::Type::HHDR | htype, buf, buf + sizeof(buf)};

  const HashsetHeader exp{
    SFHASH_SHA_1,
    "SHA-1",
    20,
    4886718345
  };

  CHECK(parse_hhdr(ch) == std::make_pair(State::HHDR, exp));
}

*/

TEST_CASE("parse_ridx") {
  const uint8_t buf[] = {
    // indices
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  const Chunk ch{Chunk::Type::RIDX, buf, buf + sizeof(buf)};

  const RecordIndex exp{ buf, buf + sizeof(buf) };

  CHECK(parse_ridx(ch) == std::make_pair(State::SBRK, exp));
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

  const Chunk ch{Chunk::Type::RHDR, buf, buf + sizeof(buf)};

  const RecordHeader exp{
    38,
    5649426,
    {
      { 0, "MD5", 16 },
      { 1, "SHA-1", 20 }
    }
  };

  CHECK(parse_rhdr(ch) == std::make_pair(State::RHDR, exp));
}
