#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/lexical_cast.hpp>

#include <fuzzy.h>

#include "fuzzy_matcher.h"
#include "hasher.h"
#include "parser.h"

using FuzzyMatcher = SFHASH_FuzzyMatcher;
using FuzzyResult  = SFHASH_FuzzyResult;

FuzzyMatcher* sfhash_create_fuzzy_matcher(const char* beg, const char* end) {
  return load_fuzzy_hashset(beg, end).release();
}

const FuzzyResult* sfhash_fuzzy_matcher_compare(FuzzyMatcher* matcher, const char* beg, const char* end) {
  return matcher->match(beg, end).release();
}

size_t sfhash_fuzzy_result_count(const SFHASH_FuzzyResult* result) {
  return result->Matches.size();
}
const char* sfhash_fuzzy_result_filename(const FuzzyResult* result, size_t i) {
  return result->filename(i);
}

const char* sfhash_fuzzy_result_query_filename(const FuzzyResult* result) {
  return result->queryFilename();
}

int sfhash_fuzzy_result_score(const FuzzyResult* result, size_t i) {
  return result->score(i);
}

void sfhash_fuzzy_destroy_match(const FuzzyResult* result) {
  delete result;
}

void sfhash_destroy_fuzzy_matcher(FuzzyMatcher* matcher) {
  delete matcher;
}

FuzzyHash::FuzzyHash(const char* a, const char* b) :
  Beg(a), End(b)
{}

std::string FuzzyHash::hash() const {
  return std::string(Beg, End-Beg);
}

uint64_t FuzzyHash::blocksize() const {
  return std::strtoull(Beg, nullptr, 10);
}

std::string FuzzyHash::block() const {
  const char* i = static_cast<const char*>(std::memchr(Beg, ':', End-Beg));
  const char* j = static_cast<const char*>(std::memchr(i + 1, ':', End - (i+1)));
  return std::string(i+1, j - (i + 1));
}

std::string FuzzyHash::double_block() const {
  const char* i = static_cast<const char*>(std::memchr(Beg, ':', End-Beg));
  const char* j = static_cast<const char*>(std::memchr(i + 1, ':', End - (i+1)));
  const char* k = static_cast<const char*>(std::memchr(j + 1, ',', End - (j+1)));
  if (!k) {
    k = End;
  }
  return std::string(j + 1, k - (j + 1));
}

std::string FuzzyHash::filename() const {
  const char* i = static_cast<const char*>(std::memchr(Beg, ':', End-Beg));
  const char* j = static_cast<const char*>(std::memchr(i + 1, ':', End - (i+1)));
  const char* k = static_cast<const char*>(std::memchr(j + 1, ',', End - (j+1)));
  std::string filename;
  if (!k) {
    filename = "";
  }
  else {
    filename = std::string(k+2, End - (k+3));
    while (filename.find("\\\"") != std::string::npos) {
      filename.replace(filename.find("\\\""), 2, "\"");
    }
  }
  return filename;
}

std::unordered_set<uint64_t> FuzzyHash::chunks() const {
  return decode_chunks(block());
}

std::unordered_set<uint64_t> FuzzyHash::double_chunks() const {
  return decode_chunks(double_block());
}

inline size_t blocksize_index(uint64_t blocksize) {
  blocksize /= 3;
  size_t result = 0;
  while (blocksize > 1) {
    ++result;
    blocksize >>= 1;
  }
  return result;
}

void FuzzyMatcher::reserve_space(const char* beg, const char* end) {
  LineIterator l(beg, end);
  const LineIterator lend(end, end);
  if (l == lend) {
    return;
  }

  // Count lines, chunks per block
  std::unordered_map<uint64_t, uint64_t> map;
  int lineno = 2;
  size_t max = 0;
  for (++l; l != lend; ++l, ++lineno) {
    if (l->first == l->second) {
      continue;
    }
    FuzzyHash hash(l->first, l->second);

    if (validate_hash(l->first, l->second)) {
      continue;
    }
    const size_t idx = blocksize_index(hash.blocksize());
    map[idx] += std::max((int)hash.block().length() - 6, 1);
    map[idx+1] += std::max((int)hash.double_block().length() - 6, 1);
    max = std::max(max, idx);
  }
  // If blocksize B is present at index I,
  // Then we'll have an entry for blocksize 2*B at I+1
  // Hence we need an array of length I+2
  const size_t num_blocksizes = max + 2;
  Hashes.reserve(lineno);
  ChunkMaps.resize(num_blocksizes);

  for (size_t i = 0; i < num_blocksizes; ++i) {
    // map[i] is the total number of chunks for this blocksize,
    // but not necessarily the number of distinct chunks
    // A factor of 2 is probably on the conservative side (i.e., will underestimate the amount of space needed)
    // for a typical (?) data set
    // TODO: can we be more scientific about this?
    ChunkMaps[i].reserve(map[i] / 2);
  }
}

void SFHASH_FuzzyMatcher::add(FuzzyHash&& hash) {
  add(hash.blocksize(), hash.chunks(), Hashes.size());
  add(2 * hash.blocksize(), hash.double_chunks(), Hashes.size());
  Hashes.push_back(hash);
}

std::unique_ptr<FuzzyResult> FuzzyMatcher::match(const char* beg, const char* end) const {
  FuzzyHash hash(beg, end);
  const auto blocksize = hash.blocksize();

  std::unordered_set<uint32_t> candidates;
  lookup_clusters(blocksize, hash.chunks(), candidates);
  lookup_clusters(2 * blocksize, hash.double_chunks(), candidates);

  const std::string query_hash = hash.hash();
  std::vector<std::pair<std::string, int>> matches;

  for (uint32_t hash_id: candidates) {
    const int score = fuzzy_compare(Hashes[hash_id].hash().c_str(), query_hash.c_str());
    if (score > 0) {
      matches.emplace_back(Hashes[hash_id].filename(), score);
    }
  }
  return  std::make_unique<FuzzyResult>(hash.filename(), std::move(matches));
}

void SFHASH_FuzzyMatcher::add(uint64_t blocksize, std::unordered_set<uint64_t>&& chunks, uint32_t hash_id) {
  for(uint64_t chunk: chunks) {
    ChunkMaps[blocksize_index(blocksize)][chunk].push_back(hash_id);
  }
}

void FuzzyMatcher::lookup_clusters(
                    uint64_t blocksize,
                    const std::unordered_set<uint64_t>& it,
                    std::unordered_set<uint32_t>& candidates) const
{
  const size_t idx = blocksize_index(blocksize);
  if (idx >= ChunkMaps.size()) {
    return;
  }

  const auto& chunks = ChunkMaps[idx];
  for (const auto& cluster: it) {
    const auto search = chunks.find(cluster);
    if (search != chunks.end()) {
      candidates.insert(search->second.begin(), search->second.end());
    }
  }
}

FuzzyResult::SFHASH_FuzzyResult(const std::string&& queryFilename, const std::vector<std::pair<std::string, int>>&& matches) :
  Matches(matches),
  QueryFilename(queryFilename)
{}

size_t FuzzyResult::count() const {
  return Matches.size();
}

const char* FuzzyResult::queryFilename() const {
  return QueryFilename.c_str();
}

const char* FuzzyResult::filename(size_t i) const {
  return Matches[i].first.c_str();
}

int FuzzyResult::score(size_t i) const {
  return Matches[i].second;
}

int validate_hash(const char* beg, const char* end) {
  // blocksize:hash1:hash2,"filename"
  const char* i = static_cast<const char*>(std::memchr(beg, ':', end-beg));
  if (!i) {
    return 1;
  }

  const char* j = static_cast<const char*>(std::memchr(i + 1, ':', end - (i+1)));
  if (!j) {
    return 1;
  }

  const char* k = static_cast<const char*>(std::memchr(j + 1, ',', end - (j+1)));
  if (!k || k[1] != '"' || end[-1] != '"') {
    return 1;
  }

  try {
    boost::lexical_cast<uint64_t>(beg, i-beg);
  } catch (const boost::bad_lexical_cast&) {
    return 1;
  }
  return 0;
}

uint64_t decode_base64(const std::string& s) {
  using base64_iterator = boost::archive::iterators::transform_width<
    boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6
  >;
  uint64_t val = 0;
  const std::string decoded(base64_iterator(s.begin()), base64_iterator(s.end()));
  std::memcpy(&val, decoded.c_str(), decoded.length());
  return val;
}

std::unordered_set<uint64_t> decode_chunks(const std::string& s) {
  // Get all of the 7-grams from the hash string,
  // base64 decode and reinterpret as (6-byte) integer
  if (s.length() == 0) {
    return { 0 };
  }
  if (s.length() < 7) {
    // Pad to 6 characters
    std::string block(s);
    block.append(6 - block.length(), '=');
    return { decode_base64(block) };
  }

  std::unordered_set<uint64_t> results;
  for (size_t i = 0; i + 7 <= s.length(); ++i) {
    results.insert(decode_base64(s.substr(i, 7)));
  }
  return results;
}

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end) {
  LineIterator l(beg, end);
  const LineIterator lend(end, end);
  if (l == lend) {
    return nullptr;
  }
  const std::string firstLine(l->first, l->second - l->first);
  if (firstLine!= "ssdeep,1.1--blocksize:hash:hash,filename") {
    return nullptr;
  }

  std::unique_ptr<FuzzyMatcher> matcher(new FuzzyMatcher);
  matcher->reserve_space(beg, end);

  int lineno = 2;
  for (++l; l != lend; ++l, ++lineno) {
    // skip empty lines
    if (l->first == l->second) {
      continue;
    }

    if (validate_hash(l->first, l->second)) {
      return nullptr;
    }
    matcher->add(FuzzyHash{l->first, l->second});
  }
  return matcher;
}
