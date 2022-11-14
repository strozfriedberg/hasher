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
#include <limits>
#include <map>
#include <numeric>
#include <ostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "error.h"
#include "hex.h"
#include "rwutil.h"
#include "util.h"
#include "hashset/util.h"
#include "hasher/hashset.h"

const std::map<
  SFHASH_HashAlgorithm,
  std::pair<
    RecordFieldDescriptor,
    void (*)(uint8_t* dst, const char* src, size_t dlen)
  >
> FIELDS{
  { SFHASH_MD5,       { RecordFieldDescriptor{SFHASH_MD5, "md5", 16 }, from_hex } },
  { SFHASH_SHA_1,     { RecordFieldDescriptor{SFHASH_SHA_1, "sha1", 20 }, from_hex } },
  { SFHASH_SHA_2_224, { RecordFieldDescriptor{SFHASH_SHA_2_224, "sha2_224", 28 }, from_hex } },
  { SFHASH_SHA_2_256, { RecordFieldDescriptor{SFHASH_SHA_2_256, "sha2_256", 32 }, from_hex } },
  { SFHASH_SHA_2_384, { RecordFieldDescriptor{SFHASH_SHA_2_384, "sha2_384", 48 }, from_hex } },
  { SFHASH_SHA_2_512, { RecordFieldDescriptor{SFHASH_SHA_2_512, "sha2_512", 64 }, from_hex } },
  { SFHASH_SHA_3_224, { RecordFieldDescriptor{SFHASH_SHA_3_224, "sha3_224", 28 }, from_hex } },
  { SFHASH_SHA_3_256, { RecordFieldDescriptor{SFHASH_SHA_3_256, "sha3_256", 32 }, from_hex } },
  { SFHASH_SHA_3_384, { RecordFieldDescriptor{SFHASH_SHA_3_384, "sha3_384", 48 }, from_hex } },
  { SFHASH_SHA_3_512, { RecordFieldDescriptor{SFHASH_SHA_3_512, "sha3_512", 64 }, from_hex } },
  { SFHASH_BLAKE3,    { RecordFieldDescriptor{SFHASH_BLAKE3, "blake3", 32 }, from_hex } },
  { SFHASH_SIZE,      { RecordFieldDescriptor{SFHASH_SIZE, "sizes", 8 }, size_to_u64 } }
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

uint32_t make_hhnn_type(uint32_t hash_type) {
  return Chunk::Type::HHDR | (std::bit_width(hash_type) - 1);
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
  const RecordFieldDescriptor& hi)
{
  return 2 + // hi.name length
         hi.name.size() +
         8 + // hi.length
         8; // hash_count
}

size_t length_hhnn(
  const RecordFieldDescriptor& hi)
{
  return length_chunk<length_hhnn_data>(hi);
}

size_t write_hhnn_data(
  const RecordFieldDescriptor& hi,
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
  const RecordFieldDescriptor& hi,
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
  const std::vector<RecordFieldDescriptor>& fields)
{
  return 8 + // record length
         8 + // record count
         std::accumulate(
           fields.begin(), fields.end(),
           0,
           [](size_t a, const RecordFieldDescriptor& hi) {
             return a +
                    2 + // hi.type
                    2 + // hi.name length
                    hi.name.length() +
                    8; // hi.length
           }
         );
}

size_t length_rhdr(
  const std::vector<RecordFieldDescriptor>& fields)
{
  return length_chunk<length_rhdr_data>(fields);
}

size_t write_rhdr_data(
  const std::vector<RecordFieldDescriptor>& fields,
  uint64_t record_count,
  char* out)
{
  const char* beg = out;

  // record length
  out += write_le<uint64_t>(
    std::accumulate(
      fields.begin(), fields.end(),
      0,
      [](uint64_t a, const RecordFieldDescriptor& hi) {
        return a + 1 + hi.length;
      }
    ),
    out
  );

  out += write_le<uint64_t>(record_count, out);

  for (const auto& hi: fields) {
    out += write_le<uint16_t>(std::bit_width(static_cast<uint32_t>(hi.type)) - 1, out);
    out += write_pstring(hi.name, out);
    out += write_le<uint64_t>(hi.length, out);
  }

  return out - beg;
}

size_t write_rhdr(
  const std::vector<RecordFieldDescriptor>& fields,
  uint64_t record_count,
  char* out)
{
  return write_chunk<write_rhdr_data>(
    out,
    "RHDR",
    fields,
    record_count
  );
}

size_t length_rdat_data(
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count)
{
  return record_count * std::accumulate(
           fields.begin(), fields.end(),
           0,
           [](size_t a, const RecordFieldDescriptor& hi) {
             return a + 1 + hi.length;
           }
         );
}

size_t length_rdat(
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count)
{
  return length_chunk<length_rdat_data>(fields, record_count);
}

size_t write_rdat_data(
  const std::vector<RecordFieldDescriptor>& fields,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out)
{
  const char* beg = out;

  for (const auto& record: records) {
    for (size_t i = 0; i < record.size(); ++i) {
      if (record[i].empty()) {
        out += write_byte(1 + fields[i].length, 0, out);
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
  const std::vector<RecordFieldDescriptor>& fields,
  const std::vector<std::vector<std::vector<uint8_t>>>& records,
  char* out)
{
  return write_chunk<write_rdat_data>(
    out,
    "RDAT",
    fields,
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
  const TableOfContents& toc,
  char* out)
{
  const char* beg = out;

  for (const auto& [offset, chtype]: toc.entries) {
    out += write_le<uint64_t>(offset, out);
    out += write_be<uint32_t>(chtype, out);
  }

  return out - beg;
}

size_t write_ftoc(
  const TableOfContents& toc,
  char* out)
{
  return write_chunk<write_ftoc_data>(
    out,
    "FTOC",
    toc
  );
}

size_t length_fend_data() {
  return 0;
}

size_t length_fend() {
  return length_chunk<length_fend_data>();
}

size_t write_fend_data(char*) {
  return 0;
}

size_t write_fend(char* out)
{
  return write_chunk<write_fend_data>(
    out,
    "FEND"
  );
}

size_t count_chunks(const std::vector<RecordFieldDescriptor>& fields) {
  size_t chunk_count = 5 + 3 * fields.size();

  for (const auto& hi: fields) {
    if (hi.type != SFHASH_SIZE) {
      ++chunk_count;
    }
  }

  return chunk_count;
}

size_t length_hset(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count)
{
  size_t chunk_count = count_chunks(fields);

  size_t len = length_magic() +
               length_ftoc(chunk_count) +
               length_fhdr(hashset_name, hashset_desc, timestamp) +
               length_rhdr(fields) +
               length_rdat(fields, record_count);

  for (const auto& hi: fields) {
    len += length_hhnn(hi);

    if (hi.type != SFHASH_SIZE) {
      len += length_hint();
    }

    len += length_alignment_padding(len, 4096);

    len += length_hdat(record_count, hi.length) +
           length_ridx(record_count);
  }

  len += length_fend();

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

void check_strlen(const char* s, const char* sname) {
  THROW_IF(
    std::strlen(s) > std::numeric_limits<uint16_t>::max(),
    sname << " is too long, maximum length is 65535 chars"
  );
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  size_t record_count,
  SFHASH_Error** err)
{
  RecordHeader rhdr;

  try {
    check_strlen(hashset_name, "hashset_name");
    check_strlen(hashset_desc, "hashset_desc");

    THROW_IF(
      record_order_length == 0,
      "record_order_length == 0, but there must be at least one record type"
    );

    std::set<SFHASH_HashAlgorithm> tset;

    rhdr.record_length = 0;

    for (size_t i = 0; i < record_order_length; ++i) {
      try {
        THROW_IF(
          !tset.emplace(record_order[i]).second,
          "duplicate hash type " << std::to_string(record_order[i])
        );

        const auto& hi = FIELDS.at(record_order[i]).first;
        rhdr.fields.emplace_back(hi);
        rhdr.record_length += 1 + hi.length;
      }
      catch (const std::out_of_range&) {
        throw std::runtime_error(
          "uknown hash type " + std::to_string(record_order[i])
        );
      }
    }
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }

  return new SFHASH_HashsetBuildCtx{
    {},
    {
      2,
      hashset_name,
      hashset_desc,
      make_timestamp()
    },
    std::move(rhdr),
    {},
    {},
    nullptr
  };
}

size_t sfhash_hashset_builder_required_size(const SFHASH_HashsetBuildCtx* bctx) {
  return length_hset(
    bctx->fhdr.name,
    bctx->fhdr.desc,
    bctx->fhdr.time,
    bctx->rhdr.fields,
    bctx->records.size()
  );
}

void sfhash_hashset_builder_set_output_buffer(
  SFHASH_HashsetBuildCtx* bctx,
  void* out)
{
  bctx->out = out;
}

void sfhash_hashset_builder_add_record(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record)
{
  std::vector<std::vector<uint8_t>> rec;

  const uint8_t* ri = static_cast<const uint8_t*>(record);
  for (const auto& hi: bctx->rhdr.fields) {
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

void check_toc(auto toc_itr, uint64_t off, uint32_t chunk_type) {
  THROW_IF(
    toc_itr->second != chunk_type || off != toc_itr->first,
    "writing " << printable_chunk_type(chunk_type) <<
    " at " << off <<
    ", expected " << printable_chunk_type(toc_itr->second) <<
    " at " << toc_itr->first
  );
}

size_t sfhash_hashset_builder_write(
  SFHASH_HashsetBuildCtx* bctx,
  SFHASH_Error** err)
{
  const auto& [ftoc, fhdr, rhdr, rdat, records, _] = *bctx;
  const auto& fields = rhdr.fields;

// TODO: records need to be written direclty to output buffer

  std::sort(bctx->records.begin(), bctx->records.end());
  bctx->records.erase(std::unique(bctx->records.begin(), bctx->records.end()), bctx->records.end());

  //
  // Determine where each chunk will go
  //

  TableOfContents toc;

  uint64_t off = 0;

  off += length_magic();

  // FTOC
  toc.entries.emplace_back(off, Chunk::Type::FTOC);
  off += length_ftoc(count_chunks(fields));

  // FHDR
  toc.entries.emplace_back(off, Chunk::Type::FHDR);
  off += length_fhdr(fhdr.name, fhdr.desc, fhdr.time);

  // RHDR
  toc.entries.emplace_back(off, Chunk::Type::RHDR);
  off += length_rhdr(fields);

  // RDAT
  toc.entries.emplace_back(off, Chunk::Type::RDAT);
  off += length_rdat(fields, records.size());

  for (auto i = 0u; i < fields.size(); ++i) {
    uint64_t hash_count = 0;
    for (auto ri = 0u; ri < records.size(); ++ri) {
      if (!records[ri][i].empty()) {
        ++hash_count;
      }
    }

    // HHnn
    toc.entries.emplace_back(off, make_hhnn_type(fields[i].type));
    off += length_hhnn(fields[i]);

    // HINT
    if (fields[i].type != SFHASH_SIZE) {
      toc.entries.emplace_back(off, Chunk::Type::HINT);
      off += length_hint();
    }

    // HDAT
    off += length_alignment_padding(off, 4096);
    toc.entries.emplace_back(off, Chunk::Type::HDAT);
    off += length_hdat(hash_count, fields[i].length);

    // RIDX
    toc.entries.emplace_back(off, Chunk::Type::RIDX);
    off += length_ridx(hash_count);
  }

  // FEND
  toc.entries.emplace_back(off, Chunk::Type::FEND);
  off += length_fend();

  //
  // Write
  //

  char* out = static_cast<char*>(bctx->out);
  const char* beg = out;

  // Magic
  out += write_magic(out);

  auto toc_itr = toc.entries.begin();

  // FTOC
  check_toc(toc_itr++, out - beg, Chunk::Type::FTOC);
  out += write_ftoc(toc, out);

  // FHDR
  check_toc(toc_itr++, out - beg, Chunk::Type::FHDR);
  out += write_fhdr(fhdr.version, fhdr.name, fhdr.desc, fhdr.time, out);

  // RHDR
  check_toc(toc_itr++, out - beg, Chunk::Type::RHDR);
  out += write_rhdr(fields, records.size(), out);

  // RDAT
  check_toc(toc_itr++, out - beg, Chunk::Type::RDAT);
  out += write_rdat(fields, records, out);

  for (auto i = 0u; i < fields.size(); ++i) {
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
    check_toc(toc_itr++, out - beg, make_hhnn_type(fields[i].type));
    out += write_hhnn(fields[i], hashes.size(), out);

    // HINT
    if (fields[i].type != SFHASH_SIZE) {
      check_toc(toc_itr++, out - beg, Chunk::Type::HINT);
      out += write_hint(make_block_bounds<8>(hashes), out);
    }

    // HDAT
    out += write_alignment_padding(out - beg, 4096, out);
    check_toc(toc_itr++, out - beg, Chunk::Type::HDAT);
    out += write_hdat(hashes, out);

    // RIDX
    check_toc(toc_itr++, out - beg, Chunk::Type::RIDX);
    out += write_ridx(ridx, out);
  }

  // FEND
  check_toc(toc_itr++, out - beg, Chunk::Type::FEND);
  out += write_fend(out);

  return out - beg;
}

void sfhash_hashset_builder_destroy(SFHASH_HashsetBuildCtx* bctx) {
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
  // read stream into a lines vector
  std::vector<std::string> lines;

  while (in) {
    std::getline(in, lines.emplace_back());
  }

  SFHASH_Error* err = nullptr;
  auto bctx = make_unique_del(
    sfhash_hashset_builder_open(
      hashset_name,
      hashset_desc,
      htypes,
      htypes_len,
      lines.size(),
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  THROW_IF(err, err->message);

  // collect the converter functions
  std::vector<void (*)(uint8_t* dst, const char* src, size_t dlen)> conv;
  for (size_t i = 0; i < htypes_len; ++i) {
    conv.push_back(FIELDS.at(htypes[i]).second);
  }

  for (size_t l = 0; l < lines.size(); ++l) {
    try {
      const std::string& line = lines[l];

      if (line.empty()) {
        continue;
      }

      const auto& cols = split(line, ' ');

      std::vector<std::vector<uint8_t>> rec;

      for (size_t i = 0; i < htypes_len; ++i) {
        if (cols[i].empty()) {
          rec.emplace_back();
        }
        else {
          const auto hi_len = bctx->rhdr.fields[i].length;
          conv[i](
            rec.emplace_back(hi_len, 0).data(),
            cols[i].c_str(),
            hi_len
          );
        }
      }

      bctx->records.push_back(std::move(rec));
    }
    catch (const std::exception& e) {
      throw std::runtime_error(
        "error parsing line " + std::to_string(l+1) + ": " + e.what()
      );
    }
  }

  const auto hset_size = sfhash_hashset_builder_required_size(bctx.get());
  out.resize(hset_size);

  sfhash_hashset_builder_set_output_buffer(bctx.get(), out.data());

//  std::cerr << "buf.size() == " << buf.size() << std::endl;

  const auto wlen = sfhash_hashset_builder_write(bctx.get(), &err);

  out.resize(wlen);
  return wlen;
}
