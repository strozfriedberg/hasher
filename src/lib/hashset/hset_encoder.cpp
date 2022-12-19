#include "hset_encoder.h"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
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
#include "hashset/field_iterator.h"
#include "hashset/field_range.h"
#include "hashset/record_iterator.h"
#include "hashset/util.h"
#include "hasher/hashset.h"
#include "util/istream_line_range.h"

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace bip = boost::interprocess;

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
  RecordIterator beg,
  RecordIterator end)
{
  std::vector<std::pair<int64_t, int64_t>> block_bounds(
    1 << BlockBits,
    {
      std::numeric_limits<int64_t>::max(),
      std::numeric_limits<int64_t>::min()
    }
  );

  const auto count = end - beg;

  for (auto i = beg; i != end; ++i) {
    const size_t e = expected_index(reinterpret_cast<const uint8_t*>(i->rec.data()), count);
    const int64_t delta = static_cast<int64_t>(i - beg) - static_cast<int64_t>(e);

    const size_t bi = static_cast<uint8_t>(i->rec[0]) >> (8 - BlockBits);
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
  const HashsetData& hdat,
  char* out)
{
  return static_cast<char*>(hdat.end) - static_cast<char*>(hdat.beg);
}

size_t write_hdat(
  const HashsetData& hdat,
  char* out)
{
  return write_chunk<write_hdat_data>(
    out,
    "HDAT",
    hdat
  );
}

size_t length_ridx_data(size_t record_count) {
  return record_count * 8;
}

size_t length_ridx(size_t record_count) {
  return length_chunk<length_ridx_data>(record_count);
}

size_t write_ridx_data(
  const RecordIndex& ridx,
  char* out)
{
  return static_cast<char*>(ridx.end) - static_cast<char*>(ridx.beg);
}

size_t write_ridx(
  const RecordIndex& ridx,
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

size_t write_rdat_record(
  const std::vector<RecordFieldDescriptor>& fields,
  const std::vector<std::vector<uint8_t>>& record,
  char* out)
{
  const char* beg = out;

  for (size_t i = 0; i < record.size(); ++i) {
    if (record[i].empty()) {
      out += write_byte(1 + fields[i].length, 0, out);
    }
    else {
      out += write_byte(1, 1, out);
      out += write_bytes(record[i].data(), record[i].size(), out);
    }
  }

  return out - beg;
}

size_t write_rdat_data(
  const RecordData& rdat,
  char* out)
{
  return static_cast<char*>(rdat.end) - static_cast<char*>(rdat.beg);
}

size_t write_rdat(
  const RecordData& rdat,
  char* out)
{
  return write_chunk<write_rdat_data>(
    out,
    "RDAT",
    rdat
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

size_t count_chunks_hashsets_only(const std::vector<RecordFieldDescriptor>& fields) {
  size_t chunk_count = 4 + 2 * fields.size();

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

size_t length_hset_records_only(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  const std::vector<RecordFieldDescriptor>& fields,
  size_t record_count)
{
  size_t len = length_magic() +
               length_ftoc(5) +
               length_fhdr(hashset_name, hashset_desc, timestamp) +
               length_rhdr(fields) +
               length_rdat(fields, record_count);

  len += length_fend();

  return len;
}

size_t length_hset_hashsets_only(
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const std::string& timestamp,
  const std::vector<RecordFieldDescriptor>& fields,
  uint64_t record_count,
  const decltype(SFHASH_HashsetBuildCtx::hsets)& hsets)
{
  size_t chunk_count = count_chunks_hashsets_only(fields);

  size_t len = length_magic() +
               length_ftoc(chunk_count) +
               length_fhdr(hashset_name, hashset_desc, timestamp) +
               length_rhdr(fields);

  for (size_t i = 0; i < fields.size(); ++i) {
    len += length_hhnn(fields[i]);

    if (fields[i].type != SFHASH_SIZE) {
      len += length_hint();
    }

    len += length_alignment_padding(len, 4096);
//    len += length_hdat(std::get<0>(hsets[i]).hash_count, std::get<0>(hsets[i]).hash_length);
    len += length_hdat(record_count, std::get<0>(hsets[i]).hash_length);
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

void write_chunks(
  char* beg,
  const TableOfContents& ftoc,
  const FileHeader& fhdr,
  const RecordHeader& rhdr,
  const RecordData& rdat,
  const std::vector<
    std::tuple<
      uint64_t,
      RecordIterator,
      RecordIterator,
      uint64_t*,
      uint64_t*
    >
  >& hb,
  const std::map<uint64_t, size_t>& off2hbidx
)
{
  char* out = beg;

  // Magic
  out += write_magic(out);

  for (const auto& [choff, chtype]: ftoc.entries) {
    out = beg + choff;

    switch (chtype) {
    case Chunk::Type::FTOC:
      write_ftoc(ftoc, out);
      break;

    case Chunk::Type::FHDR:
      write_fhdr(fhdr.version, fhdr.name, fhdr.desc, fhdr.time, out);
      break;

    case Chunk::Type::RHDR:
      write_rhdr(rhdr.fields, rhdr.record_count, out);
      break;

    case Chunk::Type::RDAT:
      write_rdat(rdat, out);
      break;

    case Chunk::Type::HINT:
      {
        const size_t i = off2hbidx.at(choff);
        write_hint(make_block_bounds<8>(std::get<1>(hb[i]), std::get<2>(hb[i])), out);
      }
      break;

    case Chunk::Type::HDAT:
      {
        const size_t i = off2hbidx.at(choff);
        HashsetData hdat{
          std::get<1>(hb[i])->rec.data(),
          std::get<2>(hb[i])->rec.data()
        };
        write_hdat(hdat, out);
      }
      break;

    case Chunk::Type::FEND:
      write_fend(out);
      break;

    case Chunk::Type::RIDX:
      {
        const size_t i = off2hbidx.at(choff);
        const RecordIndex ridx{
          std::get<3>(hb[i]),
          std::get<4>(hb[i])
        };
        write_ridx(ridx, out);
      }
      break;

    default:
      // HHnn
      {
        const size_t i = off2hbidx.at(choff);
        write_hhnn(rhdr.fields[i], std::get<2>(hb[i]) - std::get<1>(hb[i]), out);
      }
      break;
    }
  }
}

void scatter_records_to_hashset(
  const RecordHeader& rhdr,
  RecordData& rdat,
  std::vector<
    std::tuple<
      uint64_t,
      RecordIterator,
      RecordIterator,
      uint64_t*,
      uint64_t*
    >
  >& hb)
{
  RecordIterator rbeg(static_cast<uint8_t*>(rdat.beg), rhdr.record_length);
  RecordIterator rend(static_cast<uint8_t*>(rdat.end), rhdr.record_length);
  size_t recno = 0;
  // Scatter each record out to the hash sections
  for (auto i = rbeg; i != rend; ++i) {
    size_t roff = 1;
    for (auto& [hlen, hbeg, hi, ibeg, ii]: hb) {
      if (*i->rec.data() == 0x01) {
        // write the hash to its HDAT section
        std::memcpy(hi->rec.data(), i->rec.data() + roff, hlen);
        ++hi;

        // write the record index to its RIDX section
        *ii++ = i - rbeg;
      }

      roff += hlen + 1;
    }

    ++recno;
/*
    if (recno % 10000 == 0) {
      std::cerr << "scattered " << recno << " records\n";
    }
*/
  }

  std::cerr << "scattered " << recno << " records\n";

  for (auto& [hlen, hbeg, hend, ibeg, iend]: hb) {
    // Sort hashes and ridx together
    HashRecordIterator hrbeg(0, hbeg->rec.data(), hlen, ibeg);
    HashRecordIterator hrend(iend - ibeg, hbeg->rec.data(), hlen, ibeg);
    std::sort(hrbeg, hrend);
  }

  std::cerr << "sorted HDAT blocks\n";
}

// TODO: switch to a std::view for producing these lazily
std::vector<std::string_view> split(std::string_view s, char delim) {
  std::vector<std::string_view> splits;

  auto i = s.begin();
  do {
    auto j = std::find(i, s.end(), delim);
    splits.emplace_back(i, j);
    i = j != s.end() ? j + 1 : j;
  } while (i != s.end());

  return splits;
}

void write_hset(
  std::istream& in,
  const std::vector<SFHASH_HashAlgorithm>& htypes,
  const std::vector<std::pair<void (*)(uint8_t* dst, const char* src, size_t dlen), size_t>>& conv,
  const char* hset_name,
  const char* hset_desc,
  const std::filesystem::path& outfile,
  const std::filesystem::path& tmpdir,
  bool with_records,
  bool with_hashsets)
{
  SFHASH_Error* err = nullptr;

  auto bctx = make_unique_del(
    sfhash_hashset_builder_open(
      hset_name,
      hset_desc,
      htypes.data(),
      htypes.size(),
      with_records,
      with_hashsets,
      outfile.c_str(),
      tmpdir.c_str(),
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  THROW_IF(err, err->message);

  if (with_records) {
    std::vector<uint8_t> rec;
    std::string line;
    size_t lineno = 0;
    while (in) {
      std::getline(in, line);

      ++lineno;
  //    if (lineno % 10000 == 0) {
  //      std::cerr << "read " << lineno << " lines\n";
  //    }

      if (line.empty()) {
        continue;
      }

      const auto& cols = split(line, ' ');

      for (size_t i = 0; i < htypes.size(); ++i) {
        if (cols[i].empty()) {
          rec.clear();
        }
        else {
          rec.resize(conv[i].second);
          conv[i].first(
            rec.data(),
            cols[i].data(),
            conv[i].second
          );
        }

        sfhash_hashset_builder_add_hash(bctx.get(), rec.data(), rec.size());
      }
    }

  //  if (lineno % 10000) {
    std::cerr << "read " << lineno << " lines\n";
  //  }

  }
  else if (with_hashsets) {

    std::vector<uint8_t> rec;
    std::string line;
    size_t lineno = 0;
    size_t rcount = 0;

    const size_t field_count = htypes.size();

    for (const auto& line: IstreamLineRange(in)) {

      ++lineno;
  //    if (lineno % 10000 == 0) {
  //      std::cerr << "read " << lineno << " lines\n";
  //    }

      if (line.empty()) {
        continue;
      }

      const auto& cols = split(line, ' ');

      FieldRange field_range(cols, conv);

      FieldIterator field_itr = field_range.begin();
      for (size_t i = 0; i < field_count; ++i, ++field_itr) {
        sfhash_hashset_builder_add_hash(bctx.get(), field_itr->data(), field_itr->size());
      }
    }

  //  if (lineno % 10000) {
    std::cerr << "read " << lineno << " lines\n";
  //  }
  }

  sfhash_hashset_builder_write(bctx.get(), &err);
}

SFHASH_HashsetBuildCtx* sfhash_hashset_builder_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* tmp_dir,
  SFHASH_Error** err)
{
  auto bctx = make_unique_del(
    new SFHASH_HashsetBuildCtx{
      {},
      { 2, hashset_name, hashset_desc, make_timestamp() },
      { 0, 0, {} },
      {},
      {},
      write_records,
      write_hashsets,
      {},
      {},
      {},
      {},
      0
    },
    sfhash_hashset_builder_destroy
  );

  auto& rhdr = bctx->rhdr;

  // validate the args
  try {
    check_strlen(hashset_name, "hashset_name");
    check_strlen(hashset_desc, "hashset_desc");

    THROW_IF(
      record_order_length == 0,
      "record_order_length == 0, but there must be at least one record type"
    );

    std::set<SFHASH_HashAlgorithm> tset;

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
        THROW("uknown hash type " << std::to_string(record_order[i]));
      }
    }

    THROW_IF(
      !write_records && !write_hashsets,
      "at least one of records and hashsets must be written"
    );
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return nullptr;
  }

// TODO: error handling
  bctx->outfile = output_file;
  auto& outfile = bctx->outfile;

// TODO: error handling
  // touch the output file so it exists (can't resize a file ab initio)
  std::ofstream of;
  of.open(outfile);
  of.close();

  // establish locations of initial chunks

  auto& ftoc = bctx->ftoc;
  const auto& fhdr = bctx->fhdr;

  uint64_t off = 0;

  off += length_magic();

  // FTOC
  ftoc.entries.emplace_back(off, Chunk::Type::FTOC);
  off += length_ftoc(count_chunks(rhdr.fields));

  // FHDR
  ftoc.entries.emplace_back(off, Chunk::Type::FHDR);
  off += length_fhdr(fhdr.name, fhdr.desc, fhdr.time);

  if (write_records) {
    // RHDR
    ftoc.entries.emplace_back(off, Chunk::Type::RHDR);
    off += length_rhdr(rhdr.fields);

    // RDAT
    ftoc.entries.emplace_back(off, Chunk::Type::RDAT);

// TODO: error handling
    // resize the output file so the start of the RDAT data is at the end
    std::filesystem::resize_file(outfile, off + 12);

// TODO: error handling
    // open the output file ready for appending
    auto& out = bctx->out;
    out.open(outfile, std::ios::binary | std::ios::app);
  }
  else { // write_hashsets
    auto& hsets = bctx->hsets;
    auto& tmp_hashes_files = bctx->tmp_hashes_files;
    auto& tmp_hashes_out = bctx->tmp_hashes_out;

    for (const auto& field: rhdr.fields) {
      // initialize the hashsets from the RHDR fields
      hsets.emplace_back(
        HashsetHeader{ field.type, field.name, field.length, 0 },
        HashsetHint{},
        HashsetData{},
        RecordIndex{}
      );

// TODO: error handling
      // open the temp files for receiving the hashes
      const auto f = std::string(tmp_dir) + "/tmp_" + std::to_string(field.type);
      const auto& p = tmp_hashes_files.emplace_back(f);
      tmp_hashes_out.emplace_back(p, std::ios::binary | std::ios::trunc);
    }
  }

  return bctx.release();
}

void sfhash_hashset_builder_add_record(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record)
{
  auto& rhdr = bctx->rhdr;
  auto& field_pos = bctx->field_pos;

  if (bctx->with_records) {
    auto& out = bctx->out;
    out.write(static_cast<const char*>(record), rhdr.record_length);
  }
  else { // with_hashsets
    // TODO
  }

  // advance the field position
  field_pos = 0;
  // advance the record count
  ++rhdr.record_count;
}

void sfhash_hashset_builder_add_hash(
  SFHASH_HashsetBuildCtx* bctx,
  const void* record,
  size_t length)
{
// TODO: check length?

  auto& field_pos = bctx->field_pos;

  if (bctx->with_records) {
    auto& out = bctx->out;
    if (length > 0) {
      out.put(1);
      out.write(static_cast<const char*>(record), length);
    }
    else {
      // FIXME: slow
      for (size_t i = 0; i < length; ++i) {
        out.put(0);
      }
    }
  }
  else { // with_hashsets
    if (length > 0) {
      auto& out = bctx->tmp_hashes_out[field_pos];
      out.write(static_cast<const char*>(record), length);
      ++std::get<0>(bctx->hsets[field_pos]).hash_count;
    }
  }

  auto& rhdr = bctx->rhdr;

  // advance the field position
  ++field_pos;
  // advance the record count if we've finished a record
  if ((field_pos %= rhdr.fields.size()) == 0) {
    ++rhdr.record_count;
  }
}

size_t sfhash_hashset_builder_write(
  SFHASH_HashsetBuildCtx* bctx,
  SFHASH_Error** err)
{
  const auto& outfile = bctx->outfile;

  auto& ftoc = bctx->ftoc;
  const auto& fhdr = bctx->fhdr;
  auto& rhdr = bctx->rhdr;
  auto& rdat = bctx->rdat;

  uint64_t off = 0;

  if (bctx->with_records) {
// TODO: error handling
    bctx->out.close();

    const auto hset_size = bctx->with_hashsets ?
      length_hset(
        bctx->fhdr.name,
        bctx->fhdr.desc,
        bctx->fhdr.time,
        bctx->rhdr.fields,
        bctx->rhdr.record_count
      )
      :
      length_hset_records_only(
        bctx->fhdr.name,
        bctx->fhdr.desc,
        bctx->fhdr.time,
        bctx->rhdr.fields,
        bctx->rhdr.record_count
      );

    std::filesystem::resize_file(outfile, hset_size);

    bip::file_mapping fm(outfile.c_str(), bip::read_write);
    bip::mapped_region mr(fm, bip::read_write);

    char* out = static_cast<char*>(mr.get_address());

    rdat.beg = out + ftoc.entries.back().first + 12;
    rdat.end = rdat.beg + rhdr.record_count * rhdr.record_length;

    // sort the records
    RecordIterator rbeg(static_cast<uint8_t*>(rdat.beg), rhdr.record_length);
    RecordIterator rend(static_cast<uint8_t*>(rdat.end), rhdr.record_length);

    std::sort(rbeg, rend);
    rend = std::unique(rbeg, rend);

    rdat.end = rend->rec.data();
    rhdr.record_count = rend - rbeg;

    off = ftoc.entries.back().first + length_rdat(rhdr.fields, rhdr.record_count);

    std::vector<
      std::tuple<
        uint64_t,
        RecordIterator,
        RecordIterator,
        uint64_t*,
        uint64_t*
      >
    > hb;

    std::map<uint64_t, size_t> off2hbidx;

    if (bctx->with_hashsets) {
      for (const auto& field: rhdr.fields) {
        // Determine locations for each hash block
        const size_t hbidx = hb.size();

        // HHnn
        ftoc.entries.emplace_back(off, make_hhnn_type(field.type));
        off2hbidx[off] = hbidx;
        off += length_hhnn(field);

        // HINT
        if (field.type != SFHASH_SIZE) {
          ftoc.entries.emplace_back(off, Chunk::Type::HINT);
          off2hbidx[off] = hbidx;
          off += length_hint();
        }

        // HDAT
        off += length_alignment_padding(off, 4096);
        ftoc.entries.emplace_back(off, Chunk::Type::HDAT);
        off2hbidx[off] = hbidx;

        hb.emplace_back(
          field.length,
          RecordIterator(reinterpret_cast<uint8_t*>(out) + off + 12, field.length),
          RecordIterator(reinterpret_cast<uint8_t*>(out) + off + 12, field.length),
          nullptr,
          nullptr
        );

        off += length_hdat(rhdr.record_count, field.length);

        // RIDX
        ftoc.entries.emplace_back(off, Chunk::Type::RIDX);
        off2hbidx[off] = hbidx;

        std::get<4>(hb.back()) = std::get<3>(hb.back()) = reinterpret_cast<uint64_t*>(out + off + 12);

        off += length_ridx(rhdr.record_count);
      }
    }

    // FEND
    ftoc.entries.emplace_back(off, Chunk::Type::FEND);
    off += length_fend();

    if (bctx->with_hashsets) {
      scatter_records_to_hashset(rhdr, rdat, hb);
    }

    // Write
    write_chunks(out, ftoc, fhdr, rhdr, rdat, hb, off2hbidx);
  }
  else if (bctx->with_hashsets) {
    // close the temp files
    bctx->tmp_hashes_out.clear();

    for (size_t i = 0; i < bctx->hsets.size(); ++i) {
      const auto& f = bctx->tmp_hashes_files[i];
      auto fsize = std::filesystem::file_size(f);

      auto& hhdr = std::get<0>(bctx->hsets[i]);

      {
        bip::file_mapping fm(f.c_str(), bip::read_write);
        bip::mapped_region mr(fm, bip::read_write);

        char* out = static_cast<char*>(mr.get_address());

        RecordIterator hbeg(reinterpret_cast<uint8_t*>(out), hhdr.hash_length);
        RecordIterator hend(reinterpret_cast<uint8_t*>(out + fsize), hhdr.hash_length);

        std::sort(hbeg, hend);
        hend = std::unique(hbeg, hend);

        fsize = hend->rec.data() - reinterpret_cast<uint8_t*>(out);
      }

      std::filesystem::resize_file(f, fsize);
    }

    const auto hset_size = length_hset_hashsets_only(
      bctx->fhdr.name,
      bctx->fhdr.desc,
      bctx->fhdr.time,
      bctx->rhdr.fields,
      bctx->rhdr.record_count,
      bctx->hsets
    );

    std::filesystem::resize_file(outfile, hset_size);

    bip::file_mapping fm(outfile.c_str(), bip::read_write);
    bip::mapped_region mr(fm, bip::read_write);

    char* out = static_cast<char*>(mr.get_address());

    std::vector<
      std::tuple<
        uint64_t,
        RecordIterator,
        RecordIterator,
        uint64_t*,
        uint64_t*
      >
    > hb;

    std::map<uint64_t, size_t> off2hbidx;

    off = ftoc.entries.back().first + length_fhdr(fhdr.name, fhdr.desc, fhdr.time);

    for (size_t i = 0; i < rhdr.fields.size(); ++i) {
      const auto& field = rhdr.fields[i];

      // HHnn
      ftoc.entries.emplace_back(off, make_hhnn_type(field.type));
      off2hbidx[off] = i;
      off += length_hhnn(field);

      // HINT
      if (field.type != SFHASH_SIZE) {
        ftoc.entries.emplace_back(off, Chunk::Type::HINT);
        off2hbidx[off] = i;
        off += length_hint();
      }

      // HDAT
      off += length_alignment_padding(off, 4096);
      ftoc.entries.emplace_back(off, Chunk::Type::HDAT);
      off2hbidx[off] = i;

      auto& hhdr = std::get<0>(bctx->hsets[i]);
      auto& hdat = std::get<2>(bctx->hsets[i]);

      const auto& f = bctx->tmp_hashes_files[i];

      const auto fsize = std::filesystem::file_size(f);
      std::ifstream tof(f, std::ios::binary);
      tof.read(out + off + 12, fsize);
      tof.close();
      std::filesystem::remove(f);

      hdat.beg = out + off;
      hdat.end = out + off + fsize;

      RecordIterator hbeg(static_cast<uint8_t*>(hdat.beg), hhdr.hash_length);
      RecordIterator hend(static_cast<uint8_t*>(hdat.end), hhdr.hash_length);

      std::sort(hbeg, hend);
      hend = std::unique(hbeg, hend);

      hdat.end = hend->rec.data();
      hhdr.hash_count = hend - hbeg;

      hb.emplace_back(
        field.length,
        hbeg,
        hend,
        nullptr,
        nullptr
      );

      off += static_cast<uint8_t*>(hdat.end) - static_cast<uint8_t*>(hdat.beg);
    }

    // FEND
    ftoc.entries.emplace_back(off, Chunk::Type::FEND);
    off += length_fend();

    // Write
    write_chunks(out, ftoc, fhdr, rhdr, rdat, hb, off2hbidx);
  }

  std::filesystem::resize_file(outfile, off);

  return off;
}

void sfhash_hashset_builder_destroy(SFHASH_HashsetBuildCtx* bctx) {
  delete bctx;
}

const std::map<
  SFHASH_HashAlgorithm,
  std::pair<
    void (*)(uint8_t* dst, const char* src, size_t dlen),
    size_t
  >
> CONV{
  { SFHASH_MD5,       { from_hex, 16 } },
  { SFHASH_SHA_1,     { from_hex, 20 } },
  { SFHASH_SHA_2_224, { from_hex, 28 } },
  { SFHASH_SHA_2_256, { from_hex, 32 } },
  { SFHASH_SHA_2_384, { from_hex, 48 } },
  { SFHASH_SHA_2_512, { from_hex, 64 } },
  { SFHASH_SHA_3_224, { from_hex, 28 } },
  { SFHASH_SHA_3_256, { from_hex, 32 } },
  { SFHASH_SHA_3_384, { from_hex, 48 } },
  { SFHASH_SHA_3_512, { from_hex, 64 } },
  { SFHASH_BLAKE3,    { from_hex, 32 } },
  { SFHASH_SIZE,      { size_to_u64, 8 } }
};

std::vector<
  std::pair<
    void (*)(uint8_t* dst, const char* src, size_t dlen),
    size_t
  >
>
make_text_converters(const std::vector<SFHASH_HashAlgorithm>& htypes) {
  // collect the converter functions
  std::vector<
    std::pair<
      void (*)(uint8_t* dst, const char* src, size_t dlen),
      size_t
    >
  > conv;

  for (const auto& ht: htypes) {
    conv.push_back(CONV.at(ht));
  }

  return conv;
}
