#include "hashset/hset_encoder_chunks.h"

#include "cpp20.h"
#include "rwutil.h"
#include "util.h"

#include <cstring>
#include <numeric>

#include <binaryfusefilter.h>

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

size_t length_hset_hash() {
  return 32;
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
// C++20: return write_chunk<write_fhdr_data>(
  return write_chunk(
    write_fhdr_data,
    out,
    "FHDR",
    version,
    hashset_name,
    hashset_desc,
    timestamp
  );
}

uint32_t make_hhnn_type(uint32_t hash_type) {
  return Chunk::Type::HHDR | (bit_width(hash_type) - 1);
}

std::string make_hhnn_str(uint32_t hash_type) {
  // nn is stored big-endian
  hash_type = to_be<uint16_t>(bit_width(hash_type) - 1);
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
  uint64_t hash_count,
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
  uint64_t hash_count,
  char* out)
{
// C++20: return write_chunk<write_hhnn_data>(
  return write_chunk(
    write_hhnn_data,
    out,
    make_hhnn_str(hi.type).c_str(),
    hi,
    hash_count
  );
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
// C++20: return write_chunk<write_hint_data>(
  return write_chunk(
    write_hint_data,
    out,
    "HINT",
    block_bounds
  );
}

size_t length_filter_data(uint64_t hash_count) {
  // There is no function which returns the length of the data array in a
  // binary fuse filter with a given number of input elements, and computing
  // it manually is fiddly; the simplest, though aggravatinly inefficient,
  // thing to do is to allocate one, check its size, and throw it away.
  auto filter = make_unique_del(
    new binary_fuse8_t(),
    [](binary_fuse8_t* f) {
      binary_fuse8_free(f);
      delete f; // binary_fuse8_free oddly does _not_ free f
    }
  );

  const bool ok = binary_fuse8_allocate(hash_count, filter.get());
  THROW_IF(!ok, "out of memory");

  return 2 + // filter type
         sizeof(uint64_t) +
         sizeof(uint32_t) +
         sizeof(uint32_t) +
         sizeof(uint32_t) +
         sizeof(uint32_t) +
         sizeof(uint32_t) +
         filter->ArrayLength;
}

size_t length_filter(uint64_t hash_count) {
  return length_chunk<length_filter_data>(hash_count);
}

size_t write_filter_data(
  const binary_fuse8_t* filter,
  char* out)
{
  const char* beg = out;

  out += write_le<uint64_t>(filter->Seed, out);
  out += write_le<uint32_t>(filter->SegmentLength, out);
  out += write_le<uint32_t>(filter->SegmentLengthMask, out);
  out += write_le<uint32_t>(filter->SegmentCount, out);
  out += write_le<uint32_t>(filter->SegmentCountLength, out);
  out += write_le<uint32_t>(filter->ArrayLength, out);
  out += write_bytes(filter->Fingerprints, filter->ArrayLength, out);

  return out - beg;
}

size_t write_filter(
  const binary_fuse8_t* filter,
  char* out)
{
// C++20: return write_chunk<write_filter_data>(
  return write_chunk(
    write_filter_data,
    out,
    "FLTR",
    filter
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
  char* /* out */)
{
  return hdat.end - hdat.beg;
}

size_t write_hdat(
  const HashsetData& hdat,
  char* out)
{
// C++20: return write_chunk<write_hdat_data>(
  return write_chunk(
    write_hdat_data,
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
  char* /* out */)
{
  return static_cast<char*>(ridx.end) - static_cast<char*>(ridx.beg);
}

size_t write_ridx(
  const RecordIndex& ridx,
  char* out)
{
// C++20: return write_chunk<write_ridx_data>(
  return write_chunk(
    write_ridx_data,
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
    out += write_le<uint16_t>(bit_width(static_cast<uint32_t>(hi.type)) - 1, out);
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
// C++20: return write_chunk<write_rhdr_data>(
  return write_chunk(
    write_rhdr_data,
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
  char* /* out */)
{
  return rdat.end - rdat.beg;
}

size_t write_rdat(
  const RecordData& rdat,
  char* out)
{
// C++20: return write_chunk<write_rdat_data>(
  return write_chunk(
    write_rdat_data,
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
// C++20: return write_chunk<write_ftoc_data>(
  return write_chunk(
    write_ftoc_data,
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
// C++20: return write_chunk<write_fend_data>(
  return write_chunk(
    write_fend_data,
    out,
    "FEND"
  );
}
