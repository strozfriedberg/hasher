#include "hasher.h"
#include "parser.h"
#include "fuzzy_matcher.h"
#include "fuzzy_impl.h"

#include <boost/lexical_cast.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <fuzzy.h>
#include <iostream>

using FuzzyMatcher = SFHASH_FuzzyMatcher;
using FuzzyResult  = SFHASH_FuzzyResult;

inline size_t blocksize_index(uint64_t blocksize) {
  blocksize /= 3;
  size_t result = 0;
  while (blocksize > 1) {
    ++result;
    blocksize >>= 1;
  }
  return result;
}

void FuzzyMatcher::lookup_clusters(
                    uint64_t blocksize,
                    const std::unordered_set<uint64_t>& it)
{
  if (blocksize_index(blocksize) >= db.size()) {
    return;
  }

  std::unordered_set<uint32_t> candidates;
  for (auto& cluster: it) {
    auto search = db[blocksize_index(blocksize)].find(cluster);
    if (search != db[blocksize_index(blocksize)].end()) {
      candidates.insert(search->second.begin(), search->second.end());
    }
  }
  for (uint32_t hash_id: candidates) {
    int score = fuzzy_compare(hashes[hash_id].hash().c_str(), query.hash().c_str());
    if (score > 0) {
      matches.push_back(std::make_pair(hash_id, score));
    }
  }

}

FuzzyResult* sfhash_fuzzy_get_match(SFHASH_FuzzyMatcher* matcher, int i) {
  return matcher->get_match(i).release();
}

const char* sfhash_fuzzy_result_filename(FuzzyResult* result) {
  return result->filename.c_str();
}

const char* sfhash_fuzzy_result_query_filename(FuzzyResult* result) {
  return result->query_filename.c_str();
}

int sfhash_fuzzy_result_score(FuzzyResult* result) {
  return result->score;
}

void sfhash_fuzzy_destroy_match(FuzzyResult* result) {
  delete result;
}

std::unique_ptr<FuzzyResult> FuzzyMatcher::get_match(size_t i) const {
  return std::unique_ptr<FuzzyResult>(
      new FuzzyResult {
      hashes[matches[i].first].filename(),
      query.filename(),
      matches[i].second
  });
}



int FuzzyMatcher::match(const char* beg, const char* end) {
  query = FuzzyHash(beg, end);
  auto blocksize = query.blocksize();

  matches.clear();

  lookup_clusters(blocksize, query.chunks());
  lookup_clusters(2 * blocksize, query.double_chunks());

  return matches.size();
}

int sfhash_fuzzy_matcher_compare(FuzzyMatcher* matcher, const char* beg, const char* end) {
  return matcher->match(beg, end);
}

void FuzzyMatcher::reserve_space(const char* beg, const char* end) {

  int lineno = 1;
  const LineIterator lend(end, end);
  // Count lines, chunks per block
  std::map<uint64_t, uint64_t> map;
  uint64_t max = 0;
  for (LineIterator l(beg, end); l != lend; ++l, ++lineno) {
    if (lineno == 1 || l->first == l->second) {
      continue;
    }
    FuzzyHash hash(l->first, l->second);

    if (validate_hash(l->first, l->second)) {
      continue;
    }
    map[blocksize_index(hash.blocksize())]++;
    max = std::max(max, hash.blocksize());
  }
  // If blocksize B is present at index I,
  // Then we'll have an entry for blocksize 2*B at I+1
  // Hence we need an array of length I+2
  size_t num_blocksizes = blocksize_index(max) + 2;
  hashes.reserve(lineno);
  db.resize(num_blocksizes);

  for (size_t i = 0; i < num_blocksizes; ++i) {
    db[i].reserve(map[i]);
  }

}

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end) {
  std::unique_ptr<FuzzyMatcher> matcher(new FuzzyMatcher);
  matcher->reserve_space(beg, end);

  int lineno = 1;
  const LineIterator lend(end, end);
  for (LineIterator l(beg, end); l != lend; ++l, ++lineno) {
    if (lineno == 1) {
      std::string line(l->first, l->second - l->first);
      if (line != "ssdeep,1.1--blocksize:hash:hash,filename") {
        return nullptr;
      }
      continue;
    }
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

void SFHASH_FuzzyMatcher::add(FuzzyHash&& hash) {
  add(hash.blocksize(), hash.chunks(), hashes.size());
  add(2 * hash.blocksize(), hash.double_chunks(), hashes.size());
  hashes.push_back(hash);
}

void SFHASH_FuzzyMatcher::add(uint64_t blocksize, std::unordered_set<uint64_t> chunks, uint32_t hash_id) {
  for(uint64_t chunk: chunks) {
    db[blocksize_index(blocksize)][chunk].push_back(hash_id);
  }
}

FuzzyMatcher* sfhash_create_fuzzy_matcher(const char* beg, const char* end) {
  return load_fuzzy_hashset(beg, end).release();
}

void sfhash_destroy_fuzzy_matcher(FuzzyMatcher* matcher) {
  delete matcher;
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

uint64_t FuzzyHash::blocksize() const {
  std::string h = hash();
  auto i = h.find_first_of(':', 0);
  uint64_t blocksize = 0;
  try {

    blocksize = boost::lexical_cast<uint64_t>(h.substr(0, i));
  } catch(boost::bad_lexical_cast) {}
  return blocksize;

}

std::string FuzzyHash::block() const {
  std::string h = hash();
  auto i = h.find_first_of(':', 0);
  auto j = h.find_first_of(':', i + 1);
  return h.substr(i + 1, j-i-1);
}

std::string FuzzyHash::double_block() const {
  std::string h = hash();
  auto i = h.find_first_of(':', 0);
  auto j = h.find_first_of(':', i + 1);
  auto k = h.find_first_of(',', j + 1);
  return h.substr(j+1, k - j - 1);
}

std::string FuzzyHash::filename() const {
  std::string h = hash();
  auto i = h.find_first_of(':', 0);
  auto j = h.find_first_of(':', i + 1);
  auto k = h.find_first_of(',', j + 1);
  std::string filename;
  if (k == std::string::npos) {
    filename = "";
  }
  else {
    filename = h.substr(k + 2, h.length() - k - 3);
    while (filename.find("\\\"") != std::string::npos) {
      filename.replace(filename.find("\\\""), 2, "\"");
    }
  }
  return filename;
}

std::unordered_set<uint64_t> decode_chunks(const std::string& s) {
  // Get all of the 7-grams from the hash string,
  // base64 decode and reinterpret as (6-byte) integer
  using base64_iterator = boost::archive::iterators::transform_width<
    boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6
  >;
  std::string block = s;

  char buf[8] = {};
  if (block.length() == 0) {
    return { 0 };
  }
  if (block.length() < 7) {
    // Pad to 6 characters
    block.append(6 - block.length(), '=');
    std::string decoded(base64_iterator(block.begin()), base64_iterator(block.end()));
    memcpy(buf, decoded.c_str(), decoded.length());
    uint64_t val = *reinterpret_cast<const uint64_t*>(buf);
    return {val};
  }

  std::unordered_set<uint64_t> results;
  for (size_t i = 0; i + 7 <= block.length(); ++i) {
    std::string sub = block.substr(i, 7);
    std::string decoded(base64_iterator(sub.begin()), base64_iterator(sub.end()));
    memcpy(buf, decoded.c_str(), decoded.length());
    uint64_t val = *reinterpret_cast<const uint64_t*>(buf);
    results.insert(val);
  }
  return results;
}

std::unordered_set<uint64_t> FuzzyHash::chunks() const {
  return decode_chunks(block());
}

std::unordered_set<uint64_t> FuzzyHash::double_chunks() const {
  return decode_chunks(double_block());
}

std::string FuzzyHash::hash() const {
  return std::string(beg, end-beg);
}

FuzzyHash::FuzzyHash(const char* a, const char* b) :
  beg(a), end(b)
{}

FuzzyHasher::~FuzzyHasher() {
  fuzzy_free(ctx);
}

FuzzyHasher::FuzzyHasher() :
  ctx(fuzzy_new())
{}

FuzzyHasher::FuzzyHasher(const FuzzyHasher& other) :
  ctx(fuzzy_clone(other.ctx))
{}

void FuzzyHasher::update(const uint8_t* beg, const uint8_t* end) {
  if (!fuzzy_update(ctx, beg, end-beg)) {
    // TODO: error!
  }
}

void FuzzyHasher::set_total_input_length(uint64_t len) {
  if (!fuzzy_set_total_input_length(ctx, len)) {
    // TODO: error!
  }
}

void FuzzyHasher::get(void* val) {
  if (!fuzzy_digest(ctx, static_cast<char*>(val), 0)) {
    // TODO: error!
  }
}
void FuzzyHasher::reset() {
  fuzzy_free(ctx);
  ctx = fuzzy_new();
}

FuzzyHasher* FuzzyHasher::clone() const {
  return new FuzzyHasher(*this);
}

std::unique_ptr<HasherImpl> make_fuzzy_hasher() {
  return std::unique_ptr<FuzzyHasher>(new FuzzyHasher());
}
