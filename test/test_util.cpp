#include <scope/test.h>

#include <iterator>
#include <stdexcept>

#include "util.h"


SCOPE_TEST(test_read_le_8) {
  const uint8_t x[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB
  };

  const uint8_t* i = &x[0];
  SCOPE_ASSERT_EQUAL(0xEFCDAB8967452301, read_le_8(std::begin(x), i, std::end(x)));
  SCOPE_EXPECT(read_le_8(std::begin(x), i, std::end(x)), std::runtime_error);
}

SCOPE_TEST(test_write_le_8) {
  uint8_t buf[16];
  uint8_t* out = buf;

  write_le_8(0x0123456789ABCDEF, buf, out, buf + sizeof(buf));
  SCOPE_ASSERT_EQUAL(buf + 8, out);
  SCOPE_ASSERT_EQUAL(0xEF, buf[0]);
  SCOPE_ASSERT_EQUAL(0xCD, buf[1]);
  SCOPE_ASSERT_EQUAL(0xAB, buf[2]);
  SCOPE_ASSERT_EQUAL(0x89, buf[3]);
  SCOPE_ASSERT_EQUAL(0x67, buf[4]);
  SCOPE_ASSERT_EQUAL(0x45, buf[5]);
  SCOPE_ASSERT_EQUAL(0x23, buf[6]);
  SCOPE_ASSERT_EQUAL(0x01, buf[7]);
}
