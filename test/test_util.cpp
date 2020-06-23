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

SCOPE_TEST(test_write_le) {
  uint8_t buf[16];
  uint8_t* out = buf;

  write_le<1>(6, buf, out, buf + sizeof(buf));
  SCOPE_ASSERT_EQUAL(buf + 1, out);
  SCOPE_ASSERT_EQUAL(6, buf[0]);

  out = buf;
  write_le<2>(6, buf, out, buf + sizeof(buf));
  SCOPE_ASSERT_EQUAL(buf + 2, out);
  SCOPE_ASSERT_EQUAL(6, buf[0]);
  SCOPE_ASSERT_EQUAL(0, buf[1]);

  out = buf;
  write_le<4>(0x12345678, buf, out, buf + sizeof(buf));
  SCOPE_ASSERT_EQUAL(buf + 4, out);
  SCOPE_ASSERT_EQUAL(0x78, buf[0]);
  SCOPE_ASSERT_EQUAL(0x56, buf[1]);
  SCOPE_ASSERT_EQUAL(0x34, buf[2]);
  SCOPE_ASSERT_EQUAL(0x12, buf[3]);

  out = buf;
  write_le<8>(0x0123456789ABCDEF, buf, out, buf + sizeof(buf));
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
