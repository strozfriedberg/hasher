#include <scope/test.h>

#include <iterator>
#include <stdexcept>

#include "util.h"

const uint8_t x[] = {
  0x01, 0x23,
  0x45, 0x67, 0x89, 0xAB,
  0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB
};

SCOPE_TEST(test_to_uint_le) {
  SCOPE_ASSERT_EQUAL(0x2301, to_uint_le<uint16_t>(x));
  SCOPE_ASSERT_EQUAL(0xAB896745, to_uint_le<uint32_t>(x+2));
  SCOPE_ASSERT_EQUAL(0xAB8967452301EFCD, to_uint_le<uint64_t>(x+6));
}

SCOPE_TEST(test_read_le) {
  const uint8_t* i = &x[0];
  SCOPE_ASSERT_EQUAL(0x2301, read_le<uint16_t>(std::begin(x), i, std::end(x)));
  SCOPE_ASSERT_EQUAL(0xAB896745, read_le<uint32_t>(std::begin(x), i, std::end(x)));
  SCOPE_ASSERT_EQUAL(0xAB8967452301EFCD, read_le<uint64_t>(std::begin(x), i, std::end(x)));
  SCOPE_EXPECT(read_le<uint64_t>(std::begin(x), i, std::end(x)), std::runtime_error);
}

SCOPE_TEST(test_to_uint_be) {
  SCOPE_ASSERT_EQUAL(0x0123, to_uint_be<uint16_t>(x));
  SCOPE_ASSERT_EQUAL(0x456789AB, to_uint_be<uint32_t>(x+2));
  SCOPE_ASSERT_EQUAL(0xCDEF0123456789AB, to_uint_be<uint64_t>(x+6));
}

SCOPE_TEST(test_read_be) {
  const uint8_t* i = &x[0];
  SCOPE_ASSERT_EQUAL(0x0123, read_be<uint16_t>(std::begin(x), i, std::end(x)));
  SCOPE_ASSERT_EQUAL(0x456789AB, read_be<uint32_t>(std::begin(x), i, std::end(x)));
  SCOPE_ASSERT_EQUAL(0xCDEF0123456789AB, read_be<uint64_t>(std::begin(x), i, std::end(x)));
  SCOPE_EXPECT(read_be<uint64_t>(std::begin(x), i, std::end(x)), std::runtime_error);
}



