#include <ostream>
#include <stdexcept>
#include <tuple>
#include <utility>

#include "parser.h"
#include "util.h"

template <size_t N>
std::ostream& operator<<(std::ostream& o, const hash_t<N>& h) {
  return o << to_hex(h);
}

#include "pair_out.h"
#include "tuple_out.h"
#include <scope/test.h>

SCOPE_TEST(iterateLinesLF) {
  const char txt[] = "abc\ndef\ng\nhijk\n\nlmnop\n";
  //                  012 3456 78 90123 4 567890 1

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+4, txt+7));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+8, txt+9));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+14));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+15, txt+15));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+16, txt+21));
  SCOPE_ASSERT(++i == end);
}

SCOPE_TEST(iterateLinesLFNoTerminalEOL) {
  const char txt[] = "abc\ndef\ng\nhijk\n\nlmnop";
  //                  012 3456 78 90123 4 567890

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+4, txt+7));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+8, txt+9));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+14));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+15, txt+15));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+16, txt+21));
  SCOPE_ASSERT(++i == end);
}

SCOPE_TEST(iterateLinesCRLF) {
  const char txt[] = "abc\r\ndef\r\ng\r\nhijk\r\n\r\nlmnop\r\n";
  //                  012 3 4567 8 90 1 23456 7 8 9 012345 6 7

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+5, txt+8));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+11));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+13, txt+17));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+19, txt+19));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+21, txt+26));
  SCOPE_ASSERT(++i == end);
}

SCOPE_TEST(iterateLinesCRLFNoTerminalEOL) {
  const char txt[] = "abc\r\ndef\r\ng\r\nhijk\r\n\r\nlmnop";
  //                  012 3 4567 8 90 1 23456 7 8 9 012345

  LineIterator i(txt, txt + std::strlen(txt));
  const LineIterator end(txt + std::strlen(txt), txt + std::strlen(txt));

  SCOPE_ASSERT(i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt, txt+3));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+5, txt+8));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+10, txt+11));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+13, txt+17));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+19, txt+19));
  SCOPE_ASSERT(++i != end);
  SCOPE_ASSERT_EQUAL(*i, std::make_pair(txt+21, txt+26));
  SCOPE_ASSERT(++i == end);
}

SCOPE_TEST(iterateHashset1) {
  const char HSET[] =
    "a\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "b\t456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "c\t 456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "d\t456789 \t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "e\t 456789 \t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "f\t456789\t 3937e80075fc5a0f219c7d68e5e171ec7fe6dee3\n"
    "g\t456789\t3937e80075fc5a0f219c7d68e5e171ec7fe6dee3 \n"
    "h\t456789\t 3937e80075fc5a0f219c7d68e5e171ec7fe6dee3 \n"
    "filename with spaces\t0\t5e810a94c86ff057849bfa992bd176d8f743d160\n"
    "filename_only\n"
    "filename_only\t\n"
    "filename_only\t\t\n"
    "\n"
    "\t\n"
    "\t\t\n"
    "\t8675309\t561b0fb9acc2dbb5edaf595558a1e6112a1f24a0\n"
    "extra column!\t8675309\t561b0fb9acc2dbb5edaf595558a1e6112a1f24a0\textra column!\n";

  const std::tuple<uint8_t, std::string, uint64_t, sha1_t> exp[] = {
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "a", 123, to_bytes<20>("1eb328edc1794050fa64c6c62d6656d5c6b1b6b2") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "b", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "c", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "d", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "e", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "f", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "g", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "h", 456789, to_bytes<20>("3937e80075fc5a0f219c7d68e5e171ec7fe6dee3") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "filename with spaces", 0, to_bytes<20>("5e810a94c86ff057849bfa992bd176d8f743d160") },
    { HAS_FILENAME, "filename_only", 0, sha1_t() },
    { HAS_FILENAME, "filename_only", 0, sha1_t() },
    { HAS_FILENAME, "filename_only", 0, sha1_t() },
    { BLANK_LINE, "", 0, sha1_t() },
    { BLANK_LINE, "", 0, sha1_t() },
    { BLANK_LINE, "", 0, sha1_t() },
    { HAS_SIZE_AND_HASH, "", 8675309, to_bytes<20>("561b0fb9acc2dbb5edaf595558a1e6112a1f24a0") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "extra column!", 8675309, to_bytes<20>("561b0fb9acc2dbb5edaf595558a1e6112a1f24a0") }
  };

  LineIterator l(HSET, HSET + std::strlen(HSET));
  const LineIterator lend(HSET + std::strlen(HSET), HSET + std::strlen(HSET));

  for (const auto& e: exp) {
    SCOPE_ASSERT(l != lend);
    SCOPE_ASSERT_EQUAL(parse_line(l->first, l->second), e);
    ++l;
  }

  SCOPE_ASSERT(l == lend);
}

SCOPE_TEST(iterateHashsetBad) {
  const char HSET[] =
    "too short\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b\n"
    "too long\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6bbb\n"
    "hash with trailing juni\t123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6bbb junk\n"
    "bogus hash\t123\tBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUS\n"
    "missing hash\t123\t\n"
    "missing hash column\t123\n"
    "bogus size\tNAN\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "size with trailing junk\t123-\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "size with trailing junk\t123 123\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "size too small\t-1\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n"
    "size too large\t18446744073709551617\t1eb328edc1794050fa64c6c62d6656d5c6b1b6b2\n";

  LineIterator l(HSET, HSET + std::strlen(HSET));
  const LineIterator lend(HSET + std::strlen(HSET), HSET + std::strlen(HSET));

  for (int i = 0; i < 11; ++i, ++l) {
    SCOPE_ASSERT(l != lend);
    SCOPE_EXPECT(parse_line(l->first, l->second), std::runtime_error);
  }

  SCOPE_ASSERT(++l == lend);
}

SCOPE_TEST(iterateHashset2) {
  const char HSET[] =
    "filename with spaces\t0\tda39a3ee5e6b4b0d3255bfef95601890afd80709\r\n"
    "filename êèðèëëèöà\t1\t7f8fc202eb553370d4a05b446e57fef1734eca8f\r\n";

  const std::tuple<uint8_t, std::string, uint64_t, sha1_t> exp[] = {
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "filename with spaces", 0, to_bytes<20>("da39a3ee5e6b4b0d3255bfef95601890afd80709") },
    { HAS_FILENAME | HAS_SIZE_AND_HASH, "filename êèðèëëèöà", 1, to_bytes<20>("7f8fc202eb553370d4a05b446e57fef1734eca8f") }
  };

  LineIterator l(HSET, HSET + std::strlen(HSET));
  const LineIterator lend(HSET + std::strlen(HSET), HSET + std::strlen(HSET));

  for (const auto& e: exp) {
    SCOPE_ASSERT(l != lend);
    SCOPE_ASSERT_EQUAL(parse_line(l->first, l->second), e);
    ++l;
  }

  SCOPE_ASSERT(l == lend);
}
