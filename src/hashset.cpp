#include <algorithm>
#include <cstring>

#include "hasher/api.h"
#include "hash_types.h"
#include "hashset.h"
#include "throw.h"
#include "util.h"

using HashSetInfo = SFHASH_HashSetInfo;
using HashSet = SFHASH_HashSet;
using SizeSet = SFHASH_SizeSet;
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

template <size_t N>
HashSet* make_hashset(const HashSetInfo* hsinfo, const void* beg, const void* end, bool shared) {
  return new HashSetRadiusImpl<N>(
    beg, end, shared,
    hsinfo->radius == std::numeric_limits<size_t>::max() ?
      compute_radius<N>(static_cast<const std::array<uint8_t, N>*>(beg),
                        static_cast<const std::array<uint8_t, N>*>(end)) :
      hsinfo->radius
  );
}

HashSet* load_hashset(const HashSetInfo* hsinfo, const void* beg, const void* end, bool shared) {
  THROW_IF(beg > end, "beg > end!");

  const size_t exp_len = hsinfo->hashset_size * hsinfo->hash_length;
  const size_t act_len = static_cast<const char*>(end) - static_cast<const char*>(beg);

  THROW_IF(exp_len > act_len, "out of data reading hashes");
  THROW_IF(exp_len < act_len, "data trailing hashes");

  switch (hsinfo->hash_length) {
  case 16:
    return make_hashset<16>(hsinfo, beg, end, shared);
  case 20:
    return make_hashset<20>(hsinfo, beg, end, shared);
  case 28:
    return make_hashset<28>(hsinfo, beg, end, shared);
  case 32:
    return make_hashset<32>(hsinfo, beg, end, shared);
  case 48:
    return make_hashset<48>(hsinfo, beg, end, shared);
  case 64:
    return make_hashset<64>(hsinfo, beg, end, shared);
  default:
    THROW("unsupported hash size " << hsinfo->hash_length);
  }
}

HashSet* sfhash_load_hashset(
  const HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  bool shared,
  Error** err)
{
  try {
    return load_hashset(hsinfo, beg, end, shared);
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

void sfhash_destroy_hashset(HashSet* hset) { delete hset; }

bool sfhash_lookup_hashset(const HashSet* hset, const void* hash) {
  return hset->contains(static_cast<const uint8_t*>(hash));
}

SizeSet* load_sizeset(
  HashSetInfo* hsinfo,
  const uint8_t* beg,
  const uint8_t* end)
{
  THROW_IF(beg > end, "beg > end!");

  const size_t exp_len = hsinfo->hashset_size * sizeof(uint64_t);
  const size_t act_len = end - beg;

  THROW_IF(exp_len > act_len, "out of data reading sizes");
  THROW_IF(exp_len < act_len, "data trailing sizes");

  auto sset = make_unique_del(new SizeSet, sfhash_destroy_sizeset);

  const uint8_t* cur = beg;
  while (cur < end) {
    sset->sizes.insert(read_le<uint64_t>(beg, cur, end));
  }

  return sset.release();
}

SizeSet* sfhash_load_sizeset(
  HashSetInfo* hsinfo,
  const void* beg,
  const void* end,
  Error** err)
{
  try {
    return load_sizeset(hsinfo, static_cast<const uint8_t*>(beg),
                                static_cast<const uint8_t*>(end));
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

bool sfhash_lookup_sizeset(const SizeSet* sset, uint64_t size) {
  return sset->sizes.find(size) != sset->sizes.end();
}

void sfhash_destroy_sizeset(SizeSet* sset) {
  delete sset;
}

void sfhash_free_error(Error* err) {
  if (err) {
    delete[] err->message;
    delete err;
  }
}

uint32_t expected_index(const uint8_t* h, uint32_t set_size) {
  /*
   * The expected index for a hash (assuming a uniform distribution) in
   * the hash set is hash/2^(hash length) * set_size. We assume that
   * set_size fits in 32 bits, so nothing beyond the most significant 32
   * bits of the hash can make a difference for the expected index. Hence,
   * we can simplify the expected index to high/2^32 * set_size =
   * (high * set_size)/2^32. Observing that (2^32-1)^2 < (2^32)^2 = 2^64,
   * we see that (high * set_size) fits into 64 bits without overflow, so
   * can compute the expected index as (high * set_size) >> 32.
   */
  const uint64_t high32 = to_uint_be<uint32_t>(h);
  return static_cast<uint32_t>((high32 * set_size) >> 32);
}
