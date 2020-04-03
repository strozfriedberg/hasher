#include "hasher/api.h"
#include "error.h"
#include "hash_types.h"
#include "hashsetinfo.h"
#include "throw.h"
#include "util.h"

#include <algorithm>
#include <cstring>

using Error = SFHASH_Error;
using HashSetInfo = SFHASH_HashSetInfo;

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

void check_magic(const uint8_t*& i, const uint8_t* end) {
  static const uint8_t magic[] = {'S', 'e', 't', 'O', 'H', 'a', 's', 'h'};

  // read magic
  THROW_IF(i + sizeof(magic) > end, "out of data reading magic");
  THROW_IF(std::memcmp(i, magic, sizeof(magic)), "bad magic");
  i += sizeof(magic);
}

HashSetInfo* parse_header(const uint8_t* beg, const uint8_t* end) {
  THROW_IF(beg > end, "beg > end!");
  // header must be 4KB
  THROW_IF(beg + 4096 > end, "out of data reading header");

  const uint8_t* cur = beg;

  // check file magic
  check_magic(cur, end);

  auto h = make_unique_del(new HashSetInfo, sfhash_destroy_hashset_info);
  h->hashset_name = h->hashset_time = h->hashset_desc = nullptr;

  // read format version
  h->version = read_le<uint64_t>(beg, cur, end);
  THROW_IF(h->version != 1, "unsupported format version " << h->version);

  // read the rest of the header
  h->flags = read_le<uint64_t>(beg, cur, end);

  const uint64_t htype = read_le<uint64_t>(beg, cur, end);
  THROW_IF(!hash_name(htype), "unknown hash type " << htype);
  h->hash_type = static_cast<SFHASH_HashAlgorithm>(htype);

  h->hash_length = read_le<uint64_t>(beg, cur, end);
  const uint64_t exp_hash_length = hash_length(h->hash_type);
  THROW_IF(
    exp_hash_length && exp_hash_length != h->hash_length,
    "expected hash length " << exp_hash_length <<
    ", actual hash length " << h->hash_length
  );

  h->hashset_size = read_le<uint64_t>(beg, cur, end);
  h->hashset_off = read_le<uint64_t>(beg, cur, end);
  h->sizes_off = read_le<uint64_t>(beg, cur, end);
  h->radius = read_le<uint64_t>(beg, cur, end);
  read_bytes(h->hashset_sha256, sizeof(h->hashset_sha256), beg, cur, end);
  h->hashset_name = read_cstring(beg, cur, end, 96);
  h->hashset_time = read_cstring(beg, cur, end, 40);
  h->hashset_desc = read_cstring(beg, cur, end, 512);

  return h.release();
}

HashSetInfo* sfhash_load_hashset_info(
  const void* beg,
  const void* end,
  Error** err)
{
  try {
    return parse_header(static_cast<const uint8_t*>(beg),
                        static_cast<const uint8_t*>(end));
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

void sfhash_destroy_hashset_info(HashSetInfo* hsinfo) {
  if (hsinfo) {
    delete[] hsinfo->hashset_name;
    delete[] hsinfo->hashset_time;
    delete[] hsinfo->hashset_desc;
    delete hsinfo;
  }
}
