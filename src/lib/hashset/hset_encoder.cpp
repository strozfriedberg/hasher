#include "hset_encoder.h"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <istream>
#include <iterator>
#include <map>
#include <numeric>
#include <ostream>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "error.h"
#include "hex.h"
#include "rwutil.h"
#include "util.h"
#include "hashset/util.h"
#include "hasher/hashset.h"

const std::map<SFHASH_HashAlgorithm, HashInfo> HASH_INFO{
  { SFHASH_MD5,       HashInfo{SFHASH_MD5, "md5", 16, from_hex } },
  { SFHASH_SHA_1,     HashInfo{SFHASH_SHA_1, "sha1", 20, from_hex } },
  { SFHASH_SHA_2_224, HashInfo{SFHASH_SHA_2_224, "sha2_224", 28, from_hex } },
  { SFHASH_SHA_2_256, HashInfo{SFHASH_SHA_2_256, "sha2_256", 32, from_hex } },
  { SFHASH_SHA_2_384, HashInfo{SFHASH_SHA_2_384, "sha2_384", 48, from_hex } },
  { SFHASH_SHA_2_512, HashInfo{SFHASH_SHA_2_512, "sha2_512", 64, from_hex } },
  { SFHASH_SHA_3_224, HashInfo{SFHASH_SHA_3_224, "sha3_224", 28, from_hex } },
  { SFHASH_SHA_3_256, HashInfo{SFHASH_SHA_3_256, "sha3_256", 32, from_hex } },
  { SFHASH_SHA_3_384, HashInfo{SFHASH_SHA_3_384, "sha3_384", 48, from_hex } },
  { SFHASH_SHA_3_512, HashInfo{SFHASH_SHA_3_512, "sha3_512", 64, from_hex } },
  { SFHASH_BLAKE3,    HashInfo{SFHASH_BLAKE3, "blake3", 32, from_hex } },
  { SFHASH_SIZE,      HashInfo{SFHASH_SIZE, "sizes", 8, size_to_u64 } }
};

void size_to_u64(uint8_t* dst, const char* src, size_t /* dlen */) {
  THROW_IF(std::strchr(src, '-'), src << " is not nonnegative");
  *reinterpret_cast<uint64_t*>(dst) = boost::lexical_cast<uint64_t>(src);
}

template <>
size_t write_to(char* out, const void* buf, size_t len) {
  std::memcpy(out, buf, len);
  return len;
}

SFHASH_HashValues hash_chunk_data(
  const char* chunk_beg,
  const char* chunk_end)
{
  // hash the chunk data
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_SHA_2_256), sfhash_destroy_hasher
  );

  sfhash_update_hasher(hasher.get(), chunk_beg, chunk_end);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  return hashes;
}

template <auto func, typename... Args>
size_t length_chunk(Args&&... args)
{
  return 4 + // chunk type
         8 + // chunk data length
         func(std::forward<Args>(args)...) +
         32; // chunk hash
}

size_t length_alignment_padding(uint64_t pos, uint64_t align) {
  return (align - pos % align) % align;
}

size_t write_alignment_padding(uint64_t pos, uint64_t align, char* out) {
  return write_byte(length_alignment_padding(pos, align), 0, out);
}

size_t length_magic() {
  return 8;
}

size_t write_magic(char* out) {
  std::memcpy(out, "SetOHash", 8);
  return 8;
}

size_t length_fhdr_data(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp)
{
  return 8 + // version
         2 + // hashset_name length
         hashset_name.size() +
         2 + // timestamp length
         timestamp.size() +
         2 + // hashset_desc length
         hashset_desc.size();
}

size_t length_fhdr(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp)
{
  return length_chunk<length_fhdr_data>(
    hashset_name,
    hashset_desc,
    timestamp
  );
}

size_t write_fhdr_data(
  uint32_t version,
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  char* out)
{
  const char* beg = out;

  out += write_le<uint64_t>(version, out);
  out += write_pstring(hashset_name, out);
  out += write_pstring(timestamp, out);
  out += write_pstring(hashset_desc, out);

  return out - beg;
}

size_t write_fhdr(
  uint32_t version,
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  char* out)
{
  return write_chunk<write_fhdr_data>(
    out,
    "FHDR",
    version,
    hashset_name,
    hashset_desc,
    timestamp
  );
}

std::string make_hhnn_str(uint32_t hash_type) {
  // nn is stored big-endian
  hash_type = to_be<uint16_t>(std::bit_width(hash_type) - 1);
  return {
    'H',
    'H',
    reinterpret_cast<const char*>(&hash_type)[0],
    reinterpret_cast<const char*>(&hash_type)[1]
  };
}

size_t length_hhnn_data(
  const HashInfo& hi)
{
  return 2 + // hi.name length
         hi.name.size() +
         8 + // hi.length
         8; // hash_count
}

size_t length_hhnn(
  const HashInfo& hi)
{
  return length_chunk<length_hhnn_data>(hi);
}

size_t write_hhnn_data(
  const HashInfo& hi,
  size_t hash_count,
  char* out)
{
  const char* beg = out;

  out += write_pstring(hi.name, out);
  out += write_le<uint64_t>(hi.length, out);
  out += write_le<uint64_t>(hash_count, out);

  return out - beg;
}

size_t write_hhnn(
  const HashInfo& hi,
  size_t hash_count,
  char* out)
{
  return write_chunk<write_hhnn_data>(
    out,
    make_hhnn_str(hi.type).c_str(),
    hi,
    hash_count
  );
}

template <size_t BlockBits>
std::vector<std::pair<int64_t, int64_t>> make_block_bounds(
  const std::vector<std::vector<uint8_t>>& hashes)
{
  std::vector<std::pair<int64_t, int64_t>> block_bounds(
    1 << BlockBits,
    {
      std::numeric_limits<int64_t>::max(),
      std::numeric_limits<int64_t>::min()
    }
  );

  for (size_t i = 0; i < hashes.size(); ++i) {
    const size_t e = expected_index(reinterpret_cast<const uint8_t*>(hashes[i].data()), hashes.size());
    const int64_t delta = static_cast<int64_t>(i) - static_cast<int64_t>(e);

    const size_t bi = static_cast<uint8_t>(hashes[i][0]) >> (8 - BlockBits);
    block_bounds[bi].first = std::min(block_bounds[bi].first, delta);
    block_bounds[bi].second = std::max(block_bounds[bi].second, delta);
  }

  return block_bounds;
}

size_t length_hint_data() {
  return 2 + // hint type
         256 * 8 * 2; // bounds for 8-bit buckets
}

size_t length_hint() {
  return length_chunk<length_hint_data>();
}

size_t write_hint_data(
  const std::vector<std::pair<int64_t, int64_t>>& block_bounds,
  char* out)
{
/*
  for (size_t b = 0; b < block_bounds.size(); ++b) {
     std::cerr << std::hex << std::setw(2) << std::setfill('0') << b << ' '
               << std::dec
               << block_bounds[b].first << ' '
               << block_bounds[b].second << ' '
               << (block_bounds[b].second - block_bounds[b].first) << '\n';
   }
   std::cerr << '\n';
*/

  const char* beg = out;

  // TODO: set a real hint type
  out += write_be<uint16_t>(0x6208, out);  // b8 = blocks, 8-bit

  for (const auto& bb: block_bounds) {
    out += write_le<int64_t>(bb.first, out);
    out += write_le<int64_t>(bb.second, out);
  }

  return out - beg;
}

size_t write_hint(
  const std::vector<std::pair<int64_t, int64_t>>& block_bounds,
  char* out)
{
  return write_chunk<write_hint_data>(
    out,
    "HINT",
    block_bounds
  );
}

size_t length_hdat_data(size_t hash_count, size_t hash_size) {
  return hash_count * hash_size;
}

size_t length_hdat(size_t hash_count, size_t hash_size) {
  return length_chunk<length_hdat_data>(hash_count, hash_size);
}

size_t write_hdat_data(
  const std::vector<std::vector<uint8_t>>& hashes,
  char* out)
{
  const char* beg = out;

  for (const auto& h: hashes) {
    out += write_bytes(h.data(), h.size(), out);
  }

  return out - beg;
}

size_t write_hdat(
  const std::vector<std::vector<uint8_t>>& hashes,
  char* out)
{
  return write_chunk<write_hdat_data>(
    out,
    "HDAT",
    hashes
  );
}

size_t length_ridx_data(size_t record_count) {
  return record_count * 8;
}

size_t length_ridx(size_t record_count) {
  return length_chunk<length_ridx_data>(record_count);
}

size_t write_ridx_data(
  const std::vector<uint64_t>& ridx,
  char* out)
{
  const char* beg = out;

  out += write_bytes(
    reinterpret_cast<const char*>(ridx.data()),
    ridx.size() * sizeof(std::remove_reference<decltype(ridx)>::type::value_type),
    out
  );

  return out - beg;
}

size_t write_ridx(
  const std::vector<uint64_t>& ridx,
  char* out)
{
  return write_chunk<write_ridx_data>(
    out,
    "RIDX",
    ridx
  );
}

size_t length_rhdr_data(
  const std::vector<HashInfo>& hash_infos)
{
  return 8 + // record length
         8 + // record count
         std::accumulate(
           hash_infos.begin(), hash_infos.end(),
           0,
           [](size_t a, const HashInfo& hi) {
             return a +
                    2 + // hi.type
                    2 + // hi.name length
                    hi.name.length() +
                    8; // hi.length
           }
         );
}

size_t length_rhdr(
  const std::vector<HashInfo>& hash_infos)
{
  return length_chunk<length_rhdr_data>(hash_infos);
}

size_t write_rhdr_data(
  const std::vector<HashInfo>& hash_infos,
  uint64_t record_count,
  char* out)
{
  const char* beg = out;

  // record length
  out += write_le<uint64_t>(
    std::accumulate(
      hash_infos.begin(), hash_infos.end(),
      0,
      [](uint64_t a, const HashInfo& hi) {
        return a + 1 + hi.length;
      }
    ),
    out
  );

  out += write_le<uint64_t>(record_count, out);

  for (const auto& hi: hash_infos) {
    out += write_le<uint16_t>(std::bit_width(static_cast<uint32_t>(hi.type)) - 1, out);
    out += write_pstring(hi.name, out);
    out += write_le<uint64_t>(hi.length, out);
  }

  return out - beg;
}

size_t write_rhdr(
  const std::vector<HashInfo>& hash_infos,
  uint64_t record_count,
  char* out)
{
  return write_chunk<write_rhdr_data>(
    out,
    "RHDR",
    hash_infos,
    record_count
  );
}

size_t length_rdat_data(
  const std::vector<HashInfo>& hash_infos,
  size_t record_count)
{
  return record_count * std::accumulate(
           hash_infos.begin(), hash_infos.end(),
           0,
           [](size_t a, const HashInfo& hi) {
             return a + 1 + hi.length;
           }
         );
}

size_t length_rdat(
  const std::vector<HashInfo>& hash_infos,
  size_t record_count)
{
  return length_chunk<length_rdat_data>(hash_infos, record_count);
}

size_t write_rdat_data(
  const std::vector<HashInfo>& hash_infos,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out)
{
  const char* beg = out;

  for (const auto& record: records) {
    for (size_t i = 0; i < record.size(); ++i) {
      if (record[i].empty()) {
        out += write_byte(1 + hash_infos[i].length, 0, out);
      }
      else {
        out += write_byte(1, 1, out);
        out += write_bytes(record[i].data(), record[i].size(), out);
      }
    }
  }

  return out - beg;
}

size_t write_rdat(
  const std::vector<HashInfo>& hash_infos,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out)
{
  return write_chunk<write_rdat_data>(
    out,
    "RDAT",
    hash_infos,
    records
  );
}

size_t length_ftoc_data(size_t chunk_count) {
  return chunk_count * (
           8 + // offset
           4   // chunk type
         );
}

size_t length_ftoc(size_t chunk_count) {
  return length_chunk<length_ftoc_data>(chunk_count);
}

size_t write_ftoc_data(
  const std::vector<std::pair<uint64_t, std::string>>& toc,
  char* out)
{
  const char* beg = out;

  for (const auto& [offset, chtype]: toc) {
    out += write_le<uint64_t>(offset, out);
// TODO: assert that string is length 4? or make the member a char[4]?
    out += write_bytes(chtype.c_str(), 4, out);
  }

  return out - beg;
}

size_t write_ftoc(
  const std::vector<std::pair<uint64_t, std::string>>& toc,
  char* out)
{
  return write_chunk<write_ftoc_data>(
    out,
    "FTOC",
    toc
  );
}

size_t length_hset(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  const std::vector<HashInfo>& hash_infos,
  size_t record_count)
{
  size_t len = length_magic() +
               length_fhdr(hashset_name, hashset_desc, timestamp);

  for (const auto& hi: hash_infos) {
    len += length_hhnn(hi) +
           length_hint();

    len += length_alignment_padding(len, 4096);

    len += length_hdat(record_count, hi.length) +
           length_ridx(record_count);
  }

  len += length_rhdr(hash_infos) +
         length_rdat(hash_infos, record_count) +
         length_ftoc(4 + 4 * hash_infos.size());

  return len;
}

std::string make_timestamp(std::time_t tt = std::time(nullptr)) {
  // set the timestamp
  const auto tm = std::gmtime(&tt);
  // 0000-00-00T00:00:00Z
  std::string ts(20, '\0');

// TODO: check return value
// TODO: fractional seconds?
  ts.resize(std::strftime(ts.data(), ts.size(), "%FT%TZ", tm));
  return ts;
}

SFHASH_HashsetBuildCtx* sfhash_save_hashset_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  SFHASH_Error** err)
{
// TODO: would be nice to do this in-place with some sort of range adapter
  std::vector<HashInfo> hash_infos;

  for (size_t i = 0; i < record_order_length; ++i) {
// TODO: handle unrecognized type
    try {
      hash_infos.push_back(HASH_INFO.at(record_order[i]));
    }
    catch (const std::out_of_range&) {
      fill_error(err, "uknown hash type " + std::to_string(record_order[i]));
      return nullptr;
    }
  }

// TODO: check that name, desc lengths fit in 16 bits
// TODO: check that record order does not contain duplicates

  return new SFHASH_HashsetBuildCtx{
    hashset_name,
    hashset_desc,
    make_timestamp(),
    std::move(hash_infos),
    {}
  };
}

void sfhash_add_hashset_record(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record)
{
  std::vector<std::vector<uint8_t>> rec;

  const uint8_t* ri = static_cast<const uint8_t*>(record);
  for (const auto& hi: bctx->hash_infos) {
    if (*ri) {
      rec.emplace_back(ri + 1, ri + 1 + hi.length);
    }
    else {
      rec.emplace_back();
    }
    ri += 1 + hi.length;
  }

  bctx->records.push_back(std::move(rec));
}

size_t sfhash_save_hashset_size(const SFHASH_HashsetBuildCtx* bctx) {
  return length_hset(
    bctx->hashset_name,
    bctx->hashset_desc,
    bctx->timestamp,
    bctx->hash_infos,
    bctx->records.size()
  );
}

size_t sfhash_save_hashset_close(
  SFHASH_HashsetBuildCtx* bctx,
  void* outp,
  SFHASH_Error** err)
{
  char* out = static_cast<char*>(outp);

  const uint32_t version = 2;

  std::vector<std::pair<uint64_t, std::string>> toc;
  const char* beg = out;

  // Magic
  out += write_magic(out);

  const auto& [hashset_name, hashset_desc, timestamp, hash_infos, records] = *bctx;

  std::sort(bctx->records.begin(), bctx->records.end());
  bctx->records.erase(std::unique(bctx->records.begin(), bctx->records.end()), bctx->records.end());

  // FHDR
  toc.emplace_back(out - beg, "FHDR");
  out += write_fhdr(version, hashset_name, hashset_desc, timestamp, out);

  for (auto i = 0u; i < bctx->hash_infos.size(); ++i) {
    std::vector<std::pair<std::vector<uint8_t>, size_t>> recs;
    for (auto ri = 0u; ri < records.size(); ++ri) {
      if (!records[ri][i].empty()) {
        recs.emplace_back(records[ri][i], ri);
      }
    }
    std::sort(recs.begin(), recs.end());

    std::vector<std::vector<uint8_t>> hashes;
    std::vector<uint64_t> ridx;

    for (const auto& [h, ri]: recs) {
      hashes.push_back(h);
      ridx.push_back(ri);
    }

    // HHnn
    toc.emplace_back(out - beg, make_hhnn_str(hash_infos[i].type));
    out += write_hhnn(hash_infos[i], hashes.size(), out);

    // HINT
    if (hash_infos[i].type != SFHASH_SIZE) {
      toc.emplace_back(out - beg, "HINT");
      out += write_hint(make_block_bounds<8>(hashes), out);
    }

    // HDAT
    out += write_alignment_padding(out - beg, 4096, out);
    toc.emplace_back(out - beg, "HDAT");
    out += write_hdat(hashes, out);

    // RIDX
    toc.emplace_back(out - beg, "RIDX");
    out += write_ridx(ridx, out);
  }

  // RHDR
  toc.emplace_back(out - beg, "RHDR");
  out += write_rhdr(hash_infos, records.size(), out);

  // RDAT
  toc.emplace_back(out - beg, "RDAT");
  out += write_rdat(hash_infos, records, out);

  // FTOC
  toc.emplace_back(out - beg, "FTOC");
  out += write_ftoc(toc, out);

  return out - beg;
}

void sfhash_save_hashset_destroy(SFHASH_HashsetBuildCtx* bctx) {
  delete bctx;
}

// TODO: return a std::vector<std::string_view>
// even better would be to lazily produce the string_views
std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> splits;

  auto i = s.begin();
  do {
    auto j = std::find(i, s.end(), delim);
    splits.emplace_back(i, j);
    i = j != s.end() ? j + 1 : j;
  } while (i != s.end());

  return splits;
}

size_t write_hashset(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* htypes,
  size_t htypes_len,
  std::istream& in,
  std::vector<uint8_t>& out
)
{
  SFHASH_Error* err = nullptr;
  auto bctx = make_unique_del(
    sfhash_save_hashset_open(
      hashset_name,
      hashset_desc,
      htypes,
      htypes_len,
      &err
    ),
    sfhash_save_hashset_destroy
  );

// TODO: check err

  std::string line;
  while (in) {
    std::getline(in, line);

    if (line.empty()) {
      continue;
    }

    const auto& cols = split(line, ' ');

    std::vector<std::vector<uint8_t>> rec;

    for (size_t i = 0; i < bctx->hash_infos.size(); ++i) {
      if (cols[i].empty()) {
        rec.emplace_back();
      }
      else {
        rec.emplace_back(bctx->hash_infos[i].length, 0);
        bctx->hash_infos[i].conv(
          rec.back().data(),
          cols[i].c_str(),
          bctx->hash_infos[i].length
        );
      }
    }

    bctx->records.push_back(std::move(rec));
  }

  const auto hset_size = sfhash_save_hashset_size(bctx.get());
  out.resize(hset_size);

//  std::cerr << "buf.size() == " << buf.size() << std::endl;

  const auto wlen = sfhash_save_hashset_close(
    bctx.get(),
    out.data(),
    &err
  );

  out.resize(wlen);
  return wlen;
}

size_t write_hashset(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* htypes,
  size_t htypes_len,
  std::istream& in,
  std::ostream& out
)
{
  std::vector<uint8_t> ovec;

  const auto wlen = write_hashset(
    hashset_name,
    hashset_desc,
    htypes,
    htypes_len,
    in,
    ovec
  );

  out.write(reinterpret_cast<const char*>(ovec.data()), ovec.size());
  return wlen;
}
