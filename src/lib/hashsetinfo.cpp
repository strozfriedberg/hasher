#include "hasher/api.h"
#include "error.h"
#include "hash_types.h"
#include "throw.h"
#include "util.h"

#include <algorithm>
#include <cstring>

using Error = SFHASH_Error;

char* read_cstring(const uint8_t* beg, const uint8_t*& i, const uint8_t* end, size_t field_width) {
  THROW_IF(i + field_width > end, "out of data reading string at " << (i-beg));
  const uint8_t* j = std::find(i, i + field_width, '\0');
  THROW_IF(j == i + field_width, "unterminated cstring at " << (i-beg));
  char* r = new char[j - i + 1];
  std::strcpy(r, reinterpret_cast<const char*>(i));
  i += field_width;
  return r;
}

void read_bytes(uint8_t* dst, size_t len, const uint8_t* beg, const uint8_t*& i, const uint8_t* end) {
  THROW_IF(i + len > end, "out of data reading bytes at " << (i-beg));
  std::memcpy(dst, i, len);
  i += len;
}

constexpr uint8_t MAGIC[] = {'S', 'e', 't', 'O', 'H', 'a', 's', 'h'};

void write_magic(uint8_t*& dst, const uint8_t* end) {
  // write magic
  THROW_IF(dst + sizeof(MAGIC) > end, "out of space writing magic");
  std::memcpy(dst, MAGIC, sizeof(MAGIC));
  dst += sizeof(MAGIC);
}

void write_bytes(const uint8_t* src, uint8_t* beg, uint8_t*& i, uint8_t* end, size_t len) {
  THROW_IF(i + len > end, "out of space writing bytes at " << (i-beg));
  std::memcpy(i, src, len);
  i += len;
}

void write_cstring(const char* str, uint8_t* beg, uint8_t*& i, uint8_t* end, size_t field_width) {
  THROW_IF(i + field_width > end, "out of space writing string at " << (i-beg));
  std::strncpy(reinterpret_cast<char*>(i), str, field_width);
  i += field_width;
}
