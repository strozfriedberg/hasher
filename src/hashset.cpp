#include <algorithm>
#include <cstring>

#include "hasher/api.h"
#include "hashset.h"
#include "throw.h"


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
  const uint64_t high32 = (static_cast<uint32_t>(h[0]) << 24) |
                          (static_cast<uint32_t>(h[1]) << 16) |
                          (static_cast<uint32_t>(h[2]) <<  8) |
                           static_cast<uint32_t>(h[3]);
  return static_cast<uint32_t>((high32 * set_size) >> 32);
}

uint32_t read_uint32_be(const char* beg, const char*& i, const char* end) {
  THROW_IF(i + 4 > end, "out of data reading uint32_be at " << (i-beg));
  const uint32_t r = (static_cast<uint32_t>(i[0]) << 24) |
                     (static_cast<uint32_t>(i[1]) << 16) |
                     (static_cast<uint32_t>(i[2]) <<  8) |
                      static_cast<uint32_t>(i[3]);
  i += 4;
  return r;
}

uint32_t read_uint32_le(const char* beg, const char*& i, const char* end) {
  THROW_IF(i + 4 > end, "out of data reading uint32_le at " << (i-beg));
  const uint32_t r =  static_cast<uint32_t>(i[0])        |
                     (static_cast<uint32_t>(i[1]) <<  8) |
                     (static_cast<uint32_t>(i[2]) << 16) |
                     (static_cast<uint32_t>(i[3]) << 24);
  i += 4;
  return r;
}

uint64_t read_uint64_be(const char* beg, const char*& i, const char* end) {
  THROW_IF(i + 8 > end, "out of data reading uint64_be at " << (i-beg));
  const uint64_t r = (static_cast<uint64_t>(i[0]) << 56) |
                     (static_cast<uint64_t>(i[1]) << 48) |
                     (static_cast<uint64_t>(i[2]) << 40) |
                     (static_cast<uint64_t>(i[3]) << 32) |
                     (static_cast<uint64_t>(i[4]) << 24) |
                     (static_cast<uint64_t>(i[5]) << 16) |
                     (static_cast<uint64_t>(i[6]) <<  8) |
                      static_cast<uint64_t>(i[7]);
  i += 8;
  return r;
}

uint64_t read_uint64_le(const char* beg, const char*& i, const char* end) {
  THROW_IF(i + 8 > end, "out of data reading uint64_le at " << (i-beg));
  const uint64_t r =  static_cast<uint64_t>(i[0])        |
                     (static_cast<uint64_t>(i[1]) <<  8) |
                     (static_cast<uint64_t>(i[2]) << 16) |
                     (static_cast<uint64_t>(i[3]) << 24) |
                     (static_cast<uint64_t>(i[4]) << 32) |
                     (static_cast<uint64_t>(i[5]) << 40) |
                     (static_cast<uint64_t>(i[6]) << 48) |
                     (static_cast<uint64_t>(i[7]) << 56);
  i += 8;
  return r;
}

std::string read_cstring(const char* beg, const char*& i, const char* end, size_t field_width) {
  THROW_IF(i + field_width > end, "out of data reading string at " << (i-beg));
  const char* j = std::find(i, i + field_width, '\0');
  THROW_IF(j == i + field_width, "unterminated cstring at " << (i-beg));
  std::string r(i, j);
  i += field_width;
  return r;
}

void read_bytes(uint8_t* dst, size_t len, const char* beg, const char*& i, const char* end) {
  THROW_IF(i + len > end, "out of data reading bytes at " << (i-beg));
  std::memcpy(dst, i, len);
  i += len;
}

void check_magic(const char*& i, const char* end) {
  static const uint8_t magic[] = {'S', 'e', 't', 'O', 'H', 'a', 's', 'h'};

  // read magic
  THROW_IF(i + sizeof(magic) > end, "out of data reading magic");
  THROW_IF(std::memcmp(i, magic, sizeof(magic)), "bad magic");
  i += sizeof(magic);
}

const char* hash_type_name(uint64_t hash_type) {
  switch (hash_type) {
  case SF_HASH_OTHER:     return "Other";
  case SF_HASH_MD5:       return "MD5";
  case SF_HASH_SHA_1:     return "SHA-1";
  case SF_HASH_SHA_2_224: return "SHA-2-224";
  case SF_HASH_SHA_2_256: return "SHA-2-256";
  case SF_HASH_SHA_2_384: return "SHA-2-384";
  case SF_HASH_SHA_2_512: return "SHA-2-512";
  case SF_HASH_SHA_3_224: return "SHA-3-224";
  case SF_HASH_SHA_3_256: return "SHA-3-256";
  case SF_HASH_SHA_3_384: return "SHA-3-384";
  case SF_HASH_SHA_3_512: return "SHA-3-512";
  default:                return nullptr;
  }
}

uint64_t hash_type_length(SF_HASH_TYPE_ENUM hash_type) {
  switch (hash_type) {
  case SF_HASH_OTHER:     return  0;
  case SF_HASH_MD5:       return 16;
  case SF_HASH_SHA_1:     return 20;
  case SF_HASH_SHA_2_224: return 28;
  case SF_HASH_SHA_2_256: return 32;
  case SF_HASH_SHA_2_384: return 48;
  case SF_HASH_SHA_2_512: return 64;
  case SF_HASH_SHA_3_224: return 28;
  case SF_HASH_SHA_3_256: return 32;
  case SF_HASH_SHA_3_384: return 48;
  case SF_HASH_SHA_3_512: return 64;
  default:                return  0;
  }
}

Header parse_header(const char* beg, const char* end) {
  // check file magic
  check_magic(beg, end);

  Header h;
  const char* cur = beg;

  // read format version
  h.version = read_uint64_le(beg, cur, end);
  THROW_IF(h.version != 1, "unsupported format version " << h.version);

  // read the rest of the header
  h.flags = read_uint64_le(beg, cur, end);

  const uint64_t htype = read_uint64_le(beg, cur, end);
  THROW_IF(!hash_type_name(htype), "unknown hash type " << htype);
  h.hash_type = static_cast<SF_HASH_TYPE_ENUM>(htype);

  h.hash_length = read_uint64_le(beg, cur, end);
  const uint64_t exp_hash_length = hash_type_length(h.hash_type);
  THROW_IF(
    exp_hash_length && exp_hash_length != h.hash_length,
    "expected hash length " << exp_hash_length <<
    ", actual hash length " << h.hash_length
  );

  h.hashset_size = read_uint64_le(beg, cur, end);
  h.hashset_off = read_uint64_le(beg, cur, end);
  h.sizes_off = read_uint64_le(beg, cur, end);
  h.radius = read_uint64_le(beg, cur, end);
  read_bytes(h.hashset_sha256.data(), sizeof(h.hashset_sha256), beg, cur, end);
  h.hashset_name = read_cstring(beg, cur, end, 96);
  h.hashset_time = read_cstring(beg, cur, end, 40);
  h.hashset_desc = read_cstring(beg, cur, end, 512);

  return h;
}

template <size_t N>
HashSet* make_hashset(Header&& hdr) {
  return hdr.radius == std::numeric_limits<size_t>::max() ? 
    new HashSetImpl<N>(std::move(hdr)) :
    new HashSetRadiusImpl<N>(std::move(hdr));
}

HashSet* make_hashset(Header&& hdr) {
  switch (hdr.hash_length) {
  case 16:
    return make_hashset<16>(std::move(hdr));
  case 20:
    return make_hashset<20>(std::move(hdr));
  case 32:
    return make_hashset<32>(std::move(hdr));
  default:
    THROW("unsupported hash size " << hdr.hash_length); 
  }
}

void fill_error(HasherError** err, const std::string& msg) {
  *err = new HasherError;
  (*err)->message = new char[msg.length()+1];
  std::strcpy((*err)->message, msg.c_str());
}

HashSet* read_header(const char* beg, const char* end) {
  THROW_IF(beg > end, "beg > end!");
  // read 4KB header
  THROW_IF(beg + 4096 > end, "out of data reading header");
  return make_hashset(parse_header(beg, beg + 4096));
}

HashSet* sf_load_hashset_header(
  const void* beg,
  const void* end,
  HasherError** err)
{
  try {
    return read_header(static_cast<const char*>(beg),
                       static_cast<const char*>(end));
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }
}

void set_data(HashSet* hset, const void* beg, const void* end, bool shared) {
  THROW_IF(beg > end, "beg > end!");

  const size_t exp_len = hset->header().hashset_size * hset->header().hash_length;
  const size_t act_len = static_cast<const char*>(end) - static_cast<const char*>(beg);

  THROW_IF(exp_len > act_len, "out of data reading hashes");
  THROW_IF(exp_len < act_len, "data trailing hashes");
  
  hset->set_data(beg, end, shared);
}

bool sf_load_hashset_data(
  HashSet* hset,
  const void* beg,
  const void* end,
  bool shared,
  HasherError** err)
{
  try { 
    hset->set_data(beg, end, shared);
    return true;
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return false;
  }
}

void sf_destroy_hashset(HashSet* hset) { delete hset; }

int sf_lookup_hashset(const HashSet* hset, const void* hash) {
  return hset->contains(static_cast<const uint8_t*>(hash));
}

const char* sf_hashset_name(const HashSet* hset) {
  return hset->header().hashset_name.c_str();
}

const char* sf_hashset_description(const HashSet* hset) {
  return hset->header().hashset_desc.c_str();
}

size_t sf_hashset_size(const HashSet* hset) {
  return hset->header().hashset_size;
}

SF_HASH_TYPE_ENUM sf_hash_type(const HashSet* hset) {
  return hset->header().hash_type;
}

const char* sf_hash_type_name(SF_HASH_TYPE_ENUM hash_type) {
  return hash_type_name(hash_type);
}

size_t sf_hash_length(const HashSet* hset) {
  return hset->header().hash_length;
}

void sf_free_hashset_error(HasherError* err) {
  if (err) {
    delete err->message;
    delete err;
  }
}
