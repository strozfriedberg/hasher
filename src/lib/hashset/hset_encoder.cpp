#include "hset_encoder.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
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

#include "hex.h"
#include "rwutil.h"
#include "hashset/util.h"
#include "hasher/hashset.h"

void size_to_u64(uint8_t* dst, const char* src, size_t /* dlen */) {
  *reinterpret_cast<uint64_t*>(dst) = boost::lexical_cast<uint64_t>(src);
}

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

// TODO: return a std::vector<std::string_view>
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

size_t write_chunk(
  const char* chunk_type,
  const char* chunk_bytes,
  size_t chunk_length,
  std::ostream& out)
{
  size_t wlen = 0;
  out.write(chunk_type, 4);
  wlen += 4;

  wlen += write_le<uint64_t>(chunk_length, out);

  out.write(chunk_bytes, chunk_length);
  wlen += chunk_length;

  char sha256[32] = { 0 };
  // TODO: hash chunk
  out.write(sha256, sizeof(sha256));
  wlen += sizeof(sha256);

  return wlen;
}

size_t write_chunk(
  const char* chunk_type,
  std::vector<char> chunk_bytes,
  std::ostream& out)
{
  return write_chunk(chunk_type, chunk_bytes.data(), chunk_bytes.size(), out);
}

size_t write_page_alignment_padding(uint64_t pos, std::ostream& out) {
  std::vector<char> padding(4096 - pos % 4096);
  out.write(padding.data(), padding.size());
  return padding.size();
}

size_t write_magic(std::ostream& out) {
  out.write("SetOHash", 8);
  return 8;
}

size_t write_fhdr(
  uint32_t version,
  const std::string& hashset_name,
  const std::string& hashset_desc,
  const char* timestamp,
  std::ostream& out)
{
  std::vector<char> chbuf;
  write_le<uint64_t>(version, chbuf);
  write_pstring(hashset_name, chbuf);
  write_pstring(timestamp, chbuf);
  write_pstring(hashset_desc, chbuf);

  return write_chunk("FHDR", chbuf, out);
}

std::string make_hhnn_str(uint32_t hash_type) {
  // nn is stored big-endian
  // TODO: Use std::bit_width in C++20
  hash_type = to_be<uint16_t>(std::floor(std::log2(hash_type)));
  return {
    'H',
    'H',
    reinterpret_cast<const char*>(&hash_type)[0],
    reinterpret_cast<const char*>(&hash_type)[1]
  };
}

size_t write_hhnn(
  const HashInfo& hi,
  size_t hash_count,
  std::ostream& out)
{
  std::vector<char> chbuf;
  write_pstring(hi.name, chbuf);
  write_le<uint64_t>(hi.length, chbuf);
  write_le<uint64_t>(hash_count, chbuf);

  return write_chunk(make_hhnn_str(hi.type).c_str(), chbuf, out);
}

template <size_t BlockBits>
std::vector<std::pair<int64_t, int64_t>> make_block_bounds(
  const std::vector<std::vector<char>>& hashes)
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

size_t write_hint(
  const std::vector<std::vector<char>>& hashes,
  std::ostream& out)
{
  const auto block_bounds = make_block_bounds<8>(hashes);

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

  std::vector<char> chbuf;
// TODO: set a real hint type
  write_be<uint16_t>(0x6208, chbuf);  // b8 = blocks, 8-bit

  for (const auto& bb: block_bounds) {
    write_le<int64_t>(bb.first, chbuf);
    write_le<int64_t>(bb.second, chbuf);
  }

  return write_chunk("HINT", chbuf, out);
}

size_t write_hdat(
  const std::vector<std::vector<char>>& hashes,
  std::ostream& out)
{
  std::vector<char> chbuf;
  for (const auto& h: hashes) {
    chbuf.insert(chbuf.end(), h.begin(), h.end());
  }

  return write_chunk("HDAT", chbuf, out);
}

size_t write_ridx(
  const std::vector<uint64_t>& ridx,
  std::ostream& out)
{
  return write_chunk(
    "RIDX",
    reinterpret_cast<const char*>(ridx.data()),
    ridx.size() * sizeof(std::remove_reference<decltype(ridx)>::type::value_type),
    out
  );
}

size_t write_rhdr(
  const std::vector<HashInfo>& hash_infos,
  uint64_t record_count,
  std::ostream& out
) {
  std::vector<char> chbuf;
  write_le<uint64_t>(
    std::accumulate(
      hash_infos.begin(), hash_infos.end(),
      0,
      [](uint64_t a, const HashInfo& hi) {
        return a + hi.length;
      }
    ),
    chbuf
  );
  write_le<uint64_t>(record_count, chbuf);

  for (const auto& hi: hash_infos) {
    write_le<uint16_t>(hi.type, chbuf);
    write_pstring(hi.name, chbuf);
    write_le<uint64_t>(hi.length, chbuf);
  }

  return write_chunk("RHDR", chbuf, out);
}

size_t write_rdat(
  std::vector<std::vector<std::vector<char>>> records,
  std::ostream& out
) {
  std::vector<char> chbuf;
  for (const auto& record: records) {
    for (const auto& field: record) {
      chbuf.insert(chbuf.end(), field.begin(), field.end());
    }
  }

  return write_chunk("RDAT", chbuf, out);
}

size_t write_ftoc(
  std::vector<std::pair<uint64_t, std::string>>& toc,
  std::ostream& out)
{
  std::vector<char> chbuf;
  for (const auto& [offset, chtype]: toc) {
    write_le<uint64_t>(offset, chbuf);
// TODO: assert that string is length 4?
    chbuf.insert(chbuf.end(), chtype.c_str(), chtype.c_str() + 4);
  }

  return write_chunk("FTOC", chbuf, out);
}

size_t encode_hset(
  const std::string hashset_name,
  const std::string hashset_desc,
  char const* const* hash_type_names,
  size_t hash_type_names_count,
  std::istream& in,
  std::ostream& out)
{
  const uint32_t version = 2;

  std::vector<HashInfo> hash_infos;

  for (size_t i = 0; i < hash_type_names_count; ++i) {
// TODO: handle unrecognized type
    hash_infos.push_back(HASH_INFO.at(std::string(hash_type_names[i])));
  }

  // read the input into records
  std::vector<std::vector<std::vector<char>>> records;

  std::string line;
  while (in) {
    std::getline(in, line);

    if (line.empty()) {
      continue;
    }

    std::vector<std::vector<char>> rec;

    const auto& cols = split(line, ' ');

    std::transform(
      cols.begin(), cols.end(),
      hash_infos.begin(),
      std::back_inserter(rec),
      [](const auto& col, const auto& hinfo) {
        std::vector<char> b(hinfo.length);
        hinfo.conv(reinterpret_cast<uint8_t*>(b.data()), col.c_str(), hinfo.length);
        return b;
      }
    );

    records.push_back(std::move(rec));
  }

  // set the timestamp
  const auto tt = std::time(nullptr);
  const auto tm = std::gmtime(&tt);
// TODO: check max length
  char timestamp[30];

// TODO: check return value
// TODO: fractional seconds
  std::strftime(timestamp, sizeof(timestamp), "%FT%TZ", tm);

  std::vector<std::pair<uint64_t, std::string>> toc;
  uint64_t pos = 0;

  // Magic
  pos += write_magic(out);

  // FHDR
  toc.emplace_back(pos, "FHDR");
  pos += write_fhdr(version, hashset_name, hashset_desc, timestamp, out);

  for (auto i = 0u; i < hash_infos.size(); ++i) {
    std::vector<std::pair<std::vector<char>, size_t>> recs;
    for (auto ri = 0u; ri < records.size(); ++ri) {
      recs.emplace_back(records[ri][i], ri);
    }
    std::sort(recs.begin(), recs.end());

    std::vector<std::vector<char>> hashes;
    std::vector<uint64_t> ridx;

    for (const auto& [h, ri]: recs) {
      hashes.push_back(h);
      ridx.push_back(ri);
    }

    // HHnn
    toc.emplace_back(pos, make_hhnn_str(hash_infos[i].type));
    pos += write_hhnn(hash_infos[i], hashes.size(), out);

    // HINT
    if (hash_infos[i].type != SFHASH_SIZE) {
      toc.emplace_back(pos, "HINT");
      pos += write_hint(hashes, out);
    }

    // HDAT
    pos += write_page_alignment_padding(pos, out);
    toc.emplace_back(pos, "HDAT");
    pos += write_hdat(hashes, out);

    // RIDX
    toc.emplace_back(pos, "RIDX");
    pos += write_ridx(ridx, out);
  }

  // RHDR
  toc.emplace_back(pos, "RHDR");
  pos += write_rhdr(hash_infos, records.size(), out);

  // RDAT
  toc.emplace_back(pos, "RDAT");
  pos += write_rdat(records, out);

  // FTOC
  toc.emplace_back(pos, "FTOC");
  pos += write_ftoc(toc, out);

  return pos;
}
