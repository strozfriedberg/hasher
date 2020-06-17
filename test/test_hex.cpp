#include "hasher/api.h"
#include "hex.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <scope/test.h>

const std::vector<std::pair<std::string, std::vector<uint8_t>>> tests{
  { "", { } },
  { "0a", { 0x0A } },
  { "0A", { 0x0A } },
  {
    "0123456789abcdef",
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }
  },
  {
    "0123456789ABCDEF",
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }
  },
  {
    "0123456789AbCdEf",
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }
  },
  {
    "0000000000000000000000000000000000000000",
    {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }
  },
  {
    "ffffffffffffffffffffffffffffffffffffffff",
    {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }
  },
  { "1c2d", {0x1c, 0x2d} },
  { "0ff002", {0x0f, 0xf0, 0x02} },
  {
    "e2494932cf019dc84057f64878926d",
    {
      0xE2, 0x49, 0x49, 0x32, 0xCF, 0x01, 0x9D, 0xC8, 0x40, 0x57,
      0xF6, 0x48, 0x78, 0x92, 0x6D
    }
  },
  {
    "aeed3ac739d8fddfcbd1913b9e91e40417",
    {
      0xAE, 0xED, 0x3A, 0xC7, 0x39, 0xD8, 0xFD, 0xDF, 0xCB, 0xD1,
      0x91, 0x3B, 0x9E, 0x91, 0xE4, 0x04, 0x17
    }
  },
  {
    "e2494932cf019dc84057f64878926de2494932cf019dc84057f64878926de2",
    {
      0xE2, 0x49, 0x49, 0x32, 0xCF, 0x01, 0x9D, 0xC8, 0x40, 0x57,
      0xF6, 0x48, 0x78, 0x92, 0x6D, 0xE2, 0x49, 0x49, 0x32, 0xCF,
      0x01, 0x9D, 0xC8, 0x40, 0x57, 0xF6, 0x48, 0x78, 0x92, 0x6D,
      0xE2
    }
  },
  {
    "aeed3ac739d8fddfcbd1913b9e91e40417aeed3ac739d8fddfcbd1913b9e91e404",
    {
      0xAE, 0xED, 0x3A, 0xC7, 0x39, 0xD8, 0xFD, 0xDF, 0xCB, 0xD1,
      0x91, 0x3B, 0x9E, 0x91, 0xE4, 0x04, 0x17, 0xAE, 0xED, 0x3A,
      0xC7, 0x39, 0xD8, 0xFD, 0xDF, 0xCB, 0xD1, 0x91, 0x3B, 0x9E,
      0x91, 0xE4, 0x04
    }
  }
};

SCOPE_TEST(to_hexTest) {
  for (const auto& t: tests) {
    std::string exp = std::get<0>(t);
    // output is lowercased, so we lowercase the expected values
    std::transform(exp.begin(), exp.end(), exp.begin(), ::tolower);
    const auto& src = std::get<1>(t);
    std::string dst(2*src.size(), '\0');
    to_hex(&dst[0], &src[0], src.size());
    SCOPE_ASSERT_EQUAL(exp, dst);
  }
}

SCOPE_TEST(sfhash_hexTest) {
  for (const auto& t: tests) {
    std::string exp = std::get<0>(t);
    // output is lowercased, so we lowercase the expected values
    std::transform(exp.begin(), exp.end(), exp.begin(), ::tolower);
    const auto& src = std::get<1>(t);
    std::string dst(2*src.size(), '\0');
    sfhash_hex(&dst[0], &src[0], src.size());
    SCOPE_ASSERT_EQUAL(exp, dst);
  }
}

SCOPE_TEST(from_hexTest) {
  for (const auto& t: tests) {
    const auto& exp = std::get<1>(t);
    const auto& src = std::get<0>(t);
    std::vector<uint8_t> dst(exp.size(), 0);
    from_hex(&dst[0], &src[0], dst.size());
    SCOPE_ASSERT_EQUAL(exp, dst);
  }
}

SCOPE_TEST(sfhash_unhexTest) {
  for (const auto& t: tests) {
    const auto& exp = std::get<1>(t);
    const auto& src = std::get<0>(t);
    std::vector<uint8_t> dst(exp.size(), 0);
    SCOPE_ASSERT(sfhash_unhex(&dst[0], &src[0], src.size()));
    SCOPE_ASSERT_EQUAL(exp, dst);
  }
}

SCOPE_TEST(from_hexBogusTest) {
  const char nothex[] = "bogus";
  std::vector<uint8_t> dst(std::strlen(nothex), 0);
  SCOPE_EXPECT(from_hex(&dst[0], &nothex[0], dst.size()), std::runtime_error);
}

SCOPE_TEST(sfhsah_unhexBogusTest) {
  const char nothex[] = "bogus";
  std::vector<uint8_t> dst(std::strlen(nothex), 0);
  SCOPE_ASSERT(!sfhash_unhex(&dst[0], &nothex[0], std::strlen(nothex)));
}
