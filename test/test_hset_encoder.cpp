#include "hset_encoder.h"
#include "hex.h"
#include "rwutil.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string_view>
#include <tuple>
#include <utility>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("size_to_u64_good") {
  const std::initializer_list<std::pair<const char*, uint64_t>> tests = {
    { "0", 0 },
    { "42", 42 },
    { "10000000", 10000000 },
    { "18446744073709551615", 0xFFFFFFFFFFFFFFFF }
  };

  uint8_t dst[8];
  for (const auto& [in, exp]: tests) {
    DYNAMIC_SECTION(in << ' ' << exp) {
      size_to_u64(dst, in, 8);
      CHECK(*reinterpret_cast<const uint64_t*>(dst) == exp);
    }
  }
}

TEST_CASE("size_to_u64_bad") {
  const auto tests = {
    "-1",                   // too small
    "18446744073709551616", // too large
    "3.7",                  // not an integer
    "Bob"                   // not a number
  };

  uint8_t dst[8];
  for (const auto& in: tests) {
    DYNAMIC_SECTION(in << " throws") {
      CHECK_THROWS(size_to_u64(dst, in, 8));
    }
  }
}

TEST_CASE("write_chunk") {
  const auto f = [](const std::string_view x, char* out) {
    return std::copy(x.begin(), x.end(), out) - out;
  };

  const uint8_t exp[] = {
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

  std::vector<char> buf(sizeof(exp));
  CHECK(write_chunk<f>(buf.data(), "ABCD", "1234") == sizeof(exp));
  CHECK(!std::memcmp(buf.data(), exp, sizeof(exp)));
}

TEST_CASE("length_alignment_padding") {
  const std::initializer_list<std::tuple<uint64_t, uint64_t, size_t>> tests = {
    {    0, 4096,    0 },
    {    1, 4096, 4095 },
    { 4095, 4096,    1 },
    { 4096, 4096,    0 }
  };

  for (const auto& [pos, align, plen]: tests) {
    CHECK(length_alignment_padding(pos, align) == plen);
  }
}

TEST_CASE("write_alignment_padding") {
  const std::initializer_list<std::tuple<uint64_t, uint64_t, size_t>> tests = {
    {    0, 4096,    0 },
    {    1, 4096, 4095 },
    { 4095, 4096,    1 },
    { 4096, 4096,    0 }
  };

  char buf[4096];

  for (const auto& [pos, align, plen]: tests) {
    std::fill(std::begin(buf), std::end(buf), 0xFF);
    // Is it reporting the expected amount of padding?
    CHECK(write_alignment_padding(pos, align, buf) == plen);
    // Did it write at least the expected amount of padding?
    CHECK(std::all_of(std::begin(buf), std::begin(buf) + plen, [](char c){ return c == '\x00'; }));
    // Did it write no more than the expected amount of padding?
    CHECK(std::all_of(std::begin(buf) + plen, std::end(buf), [](char c){ return c == '\xFF'; }));
  }
}

TEST_CASE("length_magic") {
  CHECK(length_magic() == 8);
}

TEST_CASE("write_magic") {
  char buf[8];
  CHECK(write_magic(buf) == 8);
  CHECK(!std::memcmp(buf, "SetOHash", 8));
}

TEST_CASE("length_fhdr") {
  CHECK(length_fhdr_data("123", "4567", "890") == 24);
  CHECK(length_fhdr("123", "4567", "890") == 68);
}

template <auto func, typename... Args>
void chunk_data_tester(const std::span<const uint8_t> exp, Args&&... args) {
  std::vector<char> buf(exp.size());
  CHECK(func(std::forward<Args>(args)..., buf.data()) == exp.size());
  CHECK(!std::memcmp(buf.data(), exp.data(), exp.size()));
}

TEST_CASE("write_fhdr_data") {
  const uint32_t version = 2;
  const char name[] = "name";
  const char desc[] = "desc";
  const char ts[] = "2022-10-26T18:13:07Z";

  const uint8_t exp[] = {
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

  chunk_data_tester<write_fhdr_data>(
    std::span{exp}, version, name, desc, ts
  );
}

TEST_CASE("length_hhnn") {
  const RecordFieldDescriptor hi{SFHASH_SHA_1, "SHA-1", 20};
  CHECK(length_hhnn_data(hi) == 23);
  CHECK(length_hhnn(hi) == 67);
}

TEST_CASE("write_hhnn_data") {
  const RecordFieldDescriptor hi{SFHASH_SHA_1, "SHA-1", 20};
  const size_t hash_count = 4886718345;

  const uint8_t exp[] = {
    // hash type name length
    0x05, 0x00,
    // hash type name
    'S', 'H', 'A', '-', '1',
    // hash length
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // hash count
    0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00
  };

  chunk_data_tester<write_hhnn_data>(
    std::span{exp}, hi, hash_count
  );
}

TEST_CASE("length_hint") {
  CHECK(length_hint_data() == 4098);
  CHECK(length_hint() == 4142);
}

TEST_CASE("write_hint_data") {
  std::vector<std::pair<int64_t, int64_t>> block_bounds(256);
  for (size_t i = 0; i < block_bounds.size(); ++i) {
    block_bounds[i] = { 2*i, 2*i + 1 };
  }

  uint8_t exp[2 + sizeof(int64_t) * 2 * 256];

  // hint type
  exp[0] = 'b';
  exp[1] = 0x08;

  // block bounds
  char* cur = reinterpret_cast<char*>(exp + 2);
  for (const auto& bb: block_bounds) {
    cur += write_le<int64_t>(bb.first, cur);
    cur += write_le<int64_t>(bb.second, cur);
  }

  chunk_data_tester<write_hint_data>(
    std::span{exp}, block_bounds
  );
}

TEST_CASE("length_hdat") {
  CHECK(length_hdat_data(3914, 20) == 78280);
  CHECK(length_hdat(3914, 20) == 78324);
}

TEST_CASE("write_hdat_data") {
  const HashsetData hdat{
    reinterpret_cast<void*>(123),
    reinterpret_cast<void*>(456)
  };
  CHECK(write_hdat_data(hdat, nullptr) == 456 - 123);
}

TEST_CASE("length_ridx") {
  CHECK(length_ridx_data(134) == 1072);
  CHECK(length_ridx(134) == 1116);
}

TEST_CASE("write_ridx_data") {
  const std::vector<uint64_t> ridx{
    0,
    97,
    12345678
  };

  const uint8_t exp[] = {
    // index 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // index 1
    0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // index 2
    0x4E, 0x61, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  chunk_data_tester<write_ridx_data>(
    std::span{exp}, ridx
  );
}

TEST_CASE("length_rhdr") {
  const std::vector<RecordFieldDescriptor> fields{
    {SFHASH_MD5, "MD5", 16},
    {SFHASH_SHA_1, "SHA-1", 20}
  };
  CHECK(length_rhdr_data(fields) == 48);
  CHECK(length_rhdr(fields) == 92);
}

TEST_CASE("write_rhdr_data") {
  const std::vector<RecordFieldDescriptor> fields{
    {SFHASH_MD5, "MD5", 16},
    {SFHASH_SHA_1, "SHA-1", 20}
  };

  const uint64_t record_count = 5649426;

  const uint8_t exp[] = {
    // record length
    0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // record count
    0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00,
    //
    //hash info 0
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
    // hash info 1
    //
    // hash type
    0x01, 0x00,
    // hash type name length
    0x05, 0x00,
    // hash type name
    'S', 'H', 'A', '-', '1',
    // hash length
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  chunk_data_tester<write_rhdr_data>(
    std::span{exp}, fields, record_count
  );
}

TEST_CASE("length_rdat") {
  const std::vector<RecordFieldDescriptor> fields{
    {SFHASH_MD5, "MD5", 16},
    {SFHASH_SHA_1, "SHA-1", 20}
  };
  CHECK(length_rdat_data(fields, 87) == 3306);
  CHECK(length_rdat(fields, 87) == 3350);
}

TEST_CASE("write_rdat_data") {
  const std::vector<RecordFieldDescriptor> fields{
    {SFHASH_MD5, "MD5", 16},
    {SFHASH_SHA_1, "SHA-1", 20}
  };

  const std::vector<std::vector<std::vector<uint8_t>>> records{
    {
      {
        // MD5
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
      },
      {
        // SHA-1, not present
      }
    },
    {
      {
        // MD5, not present
      },
      {
        // SHA-1
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67
      }
    }
  };

  const uint8_t exp[] = {
    //
    // record 0
    //
    0x01, // present
    // MD5
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x00, // not present
    // SHA-1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    //
    // record 1
    //
    0x00, // not present
    // MD5
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, // present
    // SHA-1
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67
  };

  chunk_data_tester<write_rdat_data>(
    std::span{exp}, fields, records
  );
}

TEST_CASE("length_ftoc") {
  CHECK(length_ftoc_data(57) == 684);
  CHECK(length_ftoc(57) == 728);
}

TEST_CASE("write_ftoc_data") {
  const TableOfContents toc{
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

  const uint8_t exp[] = {
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

  chunk_data_tester<write_ftoc_data>(
    std::span{exp}, toc
  );
}

/*
  // for troubleshooting: dump a buffer
  std::cerr << std::hex << std::setfill('0');
  for (char c: buf) {
    std::cerr << std::setw(2) << (c & 0xFF) << ' ';
  }
  std::cerr << '\n';
*/
