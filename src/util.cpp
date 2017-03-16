#include "throw.h"
#include "util.h"

uint8_t char_to_nibble(char c) {
//  return 9*(c >> 6) + (c & 0x0F);
  if ('0' <= c && c <= '9') {
    return c - '0';
  }
  else if ('A' <= c && c <= 'F') {
    return c - 'A' + 10;
  }
  else if ('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  }
  else {
    THROW("'" << c << "' is not a hexadecimal digit");
  }
}
