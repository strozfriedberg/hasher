#include <iostream>

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

int sfhash_fuzzy_matcher_compare(FuzzyMatcher* matcher, const char* beg, const char* end) {
  return matcher->match(beg, end);
}

FuzzyResult* sfhash_fuzzy_get_match(SFHASH_FuzzyMatcher* matcher, int i) {
  return matcher->get_match(i).release();
}

const char* sfhash_fuzzy_result_filename(const FuzzyResult* result) {
  return result->filename.c_str();
}

const char* sfhash_fuzzy_result_query_filename(const FuzzyResult* result) {
  return result->query_filename.c_str();
}

int sfhash_fuzzy_result_score(const FuzzyResult* result) {
  return result->score;
}

void sfhash_fuzzy_destroy_match(FuzzyResult* result) {
  delete result;
}

void sfhash_destroy_fuzzy_matcher(FuzzyMatcher* matcher) {
  delete matcher;
}

FuzzyHash::FuzzyHash(const char* a, const char* b) :
  beg(a), end(b)
{}

std::string FuzzyHash::hash() const {
  return std::string(beg, end-beg);
}

uint64_t FuzzyHash::blocksize() const {
  return std::strtoull(beg, nullptr, 10);
}

std::string FuzzyHash::block() const {
  const char* i = static_cast<const char*>(std::memchr(beg, ':', end-beg));
  const char* j = static_cast<const char*>(std::memchr(i + 1, ':', end - (i+1)));
  return std::string(i+1, j - (i + 1));
}

std::string FuzzyHash::double_block() const {
  const char* i = static_cast<const char*>(std::memchr(beg, ':', end-beg));
  const char* j = static_cast<const char*>(std::memchr(i + 1, ':', end - (i+1)));
  const char* k = static_cast<const char*>(std::memchr(j + 1, ',', end - (j+1)));
  if (!k) {
    k = end;
  }
  return std::string(j + 1, k - (j + 1));
}

std::string FuzzyHash::filename() const {
  const char* i = static_cast<const char*>(std::memchr(beg, ':', end-beg));
  const char* j = static_cast<const char*>(std::memchr(i + 1, ':', end - (i+1)));
  const char* k = static_cast<const char*>(std::memchr(j + 1, ',', end - (j+1)));
  std::string filename;
  if (!k) {
    filename = "";
  }
  else {
    filename = std::string(k+2, end - (k+3));
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
    const auto idx = blocksize_index(hash.blocksize());
    ++map[idx];
    max = std::max(max, idx);
  }
  // If blocksize B is present at index I,
  // Then we'll have an entry for blocksize 2*B at I+1
  // Hence we need an array of length I+2
  const size_t num_blocksizes = max + 2;
  hashes.reserve(lineno);
  db.resize(num_blocksizes);

  for (size_t i = 0; i < num_blocksizes; ++i) {
    db[i].reserve(map[i]);
  }
}

void SFHASH_FuzzyMatcher::add(FuzzyHash&& hash) {
  add(hash.blocksize(), hash.chunks(), hashes.size());
  add(2 * hash.blocksize(), hash.double_chunks(), hashes.size());
  hashes.push_back(hash);
}

int FuzzyMatcher::match(const char* beg, const char* end) {
  query = FuzzyHash(beg, end);
  auto blocksize = query.blocksize();

  matches.clear();

  lookup_clusters(blocksize, query.chunks());
  lookup_clusters(2 * blocksize, query.double_chunks());

  return matches.size();
}

std::unique_ptr<FuzzyResult> FuzzyMatcher::get_match(size_t i) const {
  return std::unique_ptr<FuzzyResult>(
    new FuzzyResult {
      hashes[matches[i].first].filename(),
      query.filename(),
      matches[i].second
  });
}

void SFHASH_FuzzyMatcher::add(uint64_t blocksize, std::unordered_set<uint64_t>&& chunks, uint32_t hash_id) {
  for(uint64_t chunk: chunks) {
    db[blocksize_index(blocksize)][chunk].push_back(hash_id);
  }
}

void FuzzyMatcher::lookup_clusters(
                    uint64_t blocksize,
                    const std::unordered_set<uint64_t>& it)
{
  const auto idx = blocksize_index(blocksize);
  if (blocksize_index(blocksize) >= db.size()) {
    return;
  }

  std::unordered_set<uint32_t> candidates;
  const auto& chunks = db[idx];
  for (const auto& cluster: it) {
    const auto search = chunks.find(cluster);
    if (search != chunks.end()) {
      candidates.insert(search->second.begin(), search->second.end());
    }
  }
  for (uint32_t hash_id: candidates) {
    const int score = fuzzy_compare(hashes[hash_id].hash().c_str(), query.hash().c_str());
    if (score > 0) {
      matches.emplace_back(hash_id, score);
    }
  }
}

int validate_hash(const char* a, const char* b) {
  // blocksize:hash1:hash2,"filename"
  std::string h(a, b);

  auto i = h.find_first_of(':', 0);
  if (i == std::string::npos) {
    return 1;
  }

  auto j = h.find_first_of(':', i + 1);
  if (j == std::string::npos) {
    return 1;
  }

  if (h.back() == '\x00') {
    h.pop_back();
  }

  auto k = h.find_first_of(',', j + 1);
  if (h[k+1] != '"' ||  h[h.size() -1] != '"') {
    return 1;
  }

  try {
    boost::lexical_cast<uint64_t>(h.substr(0, i));
  } catch(boost::bad_lexical_cast) {
    return 1;
  }
  return 0;
}

std::unordered_set<uint64_t> decode_chunks(const std::string& s) {
  // Get all of the 7-grams from the hash string,
  // base64 decode and reinterpret as (6-byte) integer
  using base64_iterator = boost::archive::iterators::transform_width<
    boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6
  >;

  if (s.length() == 0) {
    return { 0 };
  }
  uint64_t val = 0;
  if (s.length() < 7) {
    // Pad to 6 characters
    std::string block(s);
    block.append(6 - block.length(), '=');
    std::string decoded(base64_iterator(block.begin()), base64_iterator(block.end()));
    std::memcpy(&val, decoded.c_str(), decoded.length());
    return {val};
  }

  std::unordered_set<uint64_t> results;
  for (size_t i = 0; i + 7 <= s.length(); ++i) {
    std::string sub = s.substr(i, 7);
    std::string decoded(base64_iterator(sub.begin()), base64_iterator(sub.end()));
    memcpy(&val, decoded.c_str(), decoded.length());
    results.insert(val);
  }
  return results;
}

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end) {
  LineIterator l(beg, end);
  const LineIterator lend(end, end);
  if (l == lend) {
    return nullptr;
  }
  std::string firstLine(l->first, l->second - l->first);
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
