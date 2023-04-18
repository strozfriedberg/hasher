#include "hashset/hset_encoder.h"

#include <algorithm>
// C++20: #include <bit>
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

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace bip = boost::interprocess;

#include "cpp20.h"
#include "error.h"
#include "hex.h"
#include "rwutil.h"
#include "util.h"
#include "hashset/hset_encoder_chunks.h"
#include "hashset/record_iterator.h"
#include "hashset/util.h"
#include "hasher/hasher.h"
#include "hasher/hashset.h"
#include "util/istream_line_range.h"

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

// TODO: unused?
template <>
size_t write_to(char* out, const void* buf, size_t len) {
  std::memcpy(out, buf, len);
  return len;
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
               length_hset_hash() +
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
               length_hset_hash() +
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
               length_hset_hash() +
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
    len += length_hdat(record_count, std::get<HashsetHeader>(hsets[i]).hash_length);
  }

  len += length_fend();

  return len;
}

std::string make_timestamp(std::time_t tt = std::time(nullptr)) {
  // set the timestamp
  const auto tm = std::gmtime(&tt);

  // 0000-00-00T00:00:00Z
  std::string ts(21, '\0'); // max length + 1; strftime wants to write a null

  const auto len = std::strftime(ts.data(), ts.size(), "%Y-%m-%dT%H:%M:%SZ", tm);
  THROW_IF(len == 0, "buffer too short for timestamp, should be impossible");
  ts.resize(len);
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

  // magic
  out += write_magic(out);

  // note the start of the hset hash
  char* hset_hash = out;
  // note the start of the data to be hashed
  const char* hset_data = hset_hash + length_hset_hash();

  // write the chunks
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
      out += write_fend(out);
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

  // hash the hset data
  auto hasher = make_unique_del(
    sfhash_create_hasher(SFHASH_SHA_2_256), sfhash_destroy_hasher
  );

  sfhash_update_hasher(hasher.get(), hset_data, out);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  write_bytes(hashes.Sha2_256, std::size(hashes.Sha2_256), hset_hash);
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
  RecordIterator rbeg(rdat.beg, rhdr.record_length);
  RecordIterator rend(rdat.end, rhdr.record_length);
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

//  std::cerr << "scattered " << recno << " records\n";

  for (auto& [hlen, hbeg, hend, ibeg, iend]: hb) {
    // Sort hashes and ridx together
    HashRecordIterator hrbeg(0, hbeg->rec.data(), hlen, ibeg);
    HashRecordIterator hrend(iend - ibeg, hbeg->rec.data(), hlen, ibeg);
    std::sort(hrbeg, hrend);
  }

//  std::cerr << "sorted HDAT blocks\n";
}

// TODO: switch to a std::view for producing these lazily
std::vector<std::string_view> split(std::string_view s, char delim) {
  std::vector<std::string_view> splits;

  auto i = s.begin();
  do {
    auto j = std::find(i, s.end(), delim);
    /*
    * This is a workaround for clang <= 14. Once 15 is out
    * we should remove this #if.
    */
// C++20: #if defined __clang__ && __clang_major__ <= 14
    splits.emplace_back(i, std::distance(i, j));
// C++20: #else
// C++20: splits.emplace_back(i, j);
// C++20: #endif
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
      outfile.string().c_str(),
      tmpdir.string().c_str(),
      &err
    ),
    sfhash_hashset_builder_destroy
  );

  THROW_IF(err, err->message);

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

    THROW_IF(cols.size() > htypes.size(), "too many columns at line " << lineno);
    THROW_IF(cols.size() < htypes.size(), "too few columns at line " << lineno);

    for (size_t i = 0; i < cols.size(); ++i) {
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

//  if (lineno % 10000) {
//  std::cerr << "read " << lineno << " lines\n";
//  }
  }

  sfhash_hashset_builder_write(bctx.get(), &err);
}

SFHASH_HashsetBuildCtx* hashset_builder_open(
  const char* hashset_name,
  const char* hashset_desc,
  const SFHASH_HashAlgorithm* record_order,
  size_t record_order_length,
  bool write_records,
  bool write_hashsets,
  const char* output_file,
  const char* tmp_dir)
{
  auto bctx = make_unique_del(
    new SFHASH_HashsetBuildCtx{
      {},
      { 2, hashset_name, make_timestamp(), hashset_desc, {} },
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

  bctx->outfile = output_file;
  auto& outfile = bctx->outfile;

  // touch the output file so it exists (can't resize a file ab initio)
  {
    std::ofstream of;
    of.exceptions(std::ofstream::failbit);
    of.open(outfile);
  }

  // establish locations of initial chunks

  auto& ftoc = bctx->ftoc;
  const auto& fhdr = bctx->fhdr;

  uint64_t off = 0;

  off += length_magic();
  off += length_hset_hash();

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

    // resize the output file so the start of the RDAT data is at the end
    std::filesystem::resize_file(outfile, off + 12);

    // open the output file ready for appending
    auto& out = bctx->out;
    out.exceptions(std::ofstream::failbit);
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

      // open the temp files for receiving the hashes
      const auto f = std::string(tmp_dir) + "/tmp_" + std::to_string(field.type);
      const auto& p = tmp_hashes_files.emplace_back(f);

      std::ofstream tof;
      tof.exceptions(std::ofstream::failbit);
      tof.open(p, std::ios::binary | std::ios::trunc);
      tmp_hashes_out.push_back(std::move(tof));
    }
  }

  return bctx.release();
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
  try {
    return hashset_builder_open(
      hashset_name,
      hashset_desc,
      record_order,
      record_order_length,
      write_records,
      write_hashsets,
      output_file,
      tmp_dir
    );
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return 0;
  }
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
    // TODO: implement
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
      std::vector<char> buf(length, 0);
      out.write(buf.data(), length);
    }
  }
  else { // with_hashsets
    if (length > 0) {
      auto& out = bctx->tmp_hashes_out[field_pos];
      out.write(static_cast<const char*>(record), length);
      ++std::get<HashsetHeader>(bctx->hsets[field_pos]).hash_count;
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

uint64_t hashset_builder_write(SFHASH_HashsetBuildCtx* bctx) {
  const auto& outfile = bctx->outfile;

  auto& ftoc = bctx->ftoc;
  const auto& fhdr = bctx->fhdr;
  auto& rhdr = bctx->rhdr;
  auto& rdat = bctx->rdat;

  uint64_t off = 0;

  if (bctx->with_records) {
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

    bip::file_mapping fm(outfile.string().c_str(), bip::read_write);
    bip::mapped_region mr(fm, bip::read_write);

    uint8_t* out = static_cast<uint8_t*>(mr.get_address());

    rdat.beg = out + ftoc.entries.back().first + 12;
    rdat.end = rdat.beg + rhdr.record_count * rhdr.record_length;

    // sort the records
    RecordIterator rbeg(rdat.beg, rhdr.record_length);
    RecordIterator rend(rdat.end, rhdr.record_length);

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
          RecordIterator(out + off + 12, field.length),
          RecordIterator(out + off + 12, field.length),
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
    write_chunks(reinterpret_cast<char*>(out), ftoc, fhdr, rhdr, rdat, hb, off2hbidx);
  }
  else if (bctx->with_hashsets) {
    // close the temp files
    bctx->tmp_hashes_out.clear();

    for (size_t i = 0; i < bctx->hsets.size(); ++i) {
      const auto& f = bctx->tmp_hashes_files[i];
      auto fsize = std::filesystem::file_size(f);

      auto& hhdr = std::get<HashsetHeader>(bctx->hsets[i]);

      {
        bip::file_mapping fm(f.string().c_str(), bip::read_write);
        bip::mapped_region mr(fm, bip::read_write);

        uint8_t* out = static_cast<uint8_t*>(mr.get_address());

        RecordIterator hbeg(out, hhdr.hash_length);
        RecordIterator hend(out + fsize, hhdr.hash_length);

        std::sort(hbeg, hend);
        hend = std::unique(hbeg, hend);

        fsize = hend->rec.data() - out;
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

    bip::file_mapping fm(outfile.string().c_str(), bip::read_write);
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

      auto& hhdr = std::get<HashsetHeader>(bctx->hsets[i]);
      auto& hdat = std::get<HashsetData>(bctx->hsets[i]);

      const auto& f = bctx->tmp_hashes_files[i];

      const auto fsize = std::filesystem::file_size(f);

      {
        std::ifstream tif;
        tif.exceptions(std::ifstream::failbit);
        tif.open(f, std::ios::binary);
        tif.read(out + off + 12, fsize);
      }
      std::filesystem::remove(f);

      hdat.beg = reinterpret_cast<uint8_t*>(out) + off + 12;
      hdat.end = hdat.beg + fsize;

      RecordIterator hbeg(hdat.beg, hhdr.hash_length);
      RecordIterator hend(hdat.end, hhdr.hash_length);

      hhdr.hash_count = hend - hbeg;

      hb.emplace_back(
        field.length,
        hbeg,
        hend,
        nullptr,
        nullptr
      );

      off += length_hdat(hhdr.hash_count, hhdr.hash_length);
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

uint64_t sfhash_hashset_builder_write(
  SFHASH_HashsetBuildCtx* bctx,
  SFHASH_Error** err)
{
  try {
    return hashset_builder_write(bctx);
  }
  catch (const std::exception& e) {
    fill_error(err, e.what());
    return 0;
  }
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
