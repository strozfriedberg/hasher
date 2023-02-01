#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/lexical_cast.hpp>

#include <fuzzy.h>

#include <algorithm>

#include "fuzzy_matcher.h"
#include "parser.h"

using FuzzyMatcher = SFHASH_FuzzyMatcher;
using FuzzyResult  = SFHASH_FuzzyResult;

FuzzyMatcher* sfhash_create_fuzzy_matcher(const void* beg, const void* end) {
  return load_fuzzy_hashset(static_cast<const char*>(beg),
                            static_cast<const char*>(end)).release();
}

FuzzyResult* sfhash_fuzzy_matcher_compare(FuzzyMatcher* matcher,
                                          const void* beg,
                                          const void* end) {
  return matcher->match(static_cast<const char*>(beg),
                        static_cast<const char*>(end)).release();
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

void sfhash_destroy_fuzzy_match(FuzzyResult* result) {
  delete result;
}

void sfhash_destroy_fuzzy_matcher(FuzzyMatcher* matcher) {
  delete matcher;
}

FuzzyHash::FuzzyHash(const char* a, const char* b):
  /*
  * This is a workaround for clang <= 14. Once 15 is out
  * we should remove this #if.
  */
// C++20: #if defined __clang__ && __clang_major__ <= 14
  Data(a, std::distance(a, b))
// C++20: #else
// C++20: Data(a, b)
// C++20: #endif
{
  const char* i = std::find(std::begin(Data), std::end(Data), ':');
  const char* j = std::find(i + 1, std::end(Data), ':');
  const char* k = std::find(j + 1, std::end(Data), ',');
// C++20: #if defined __clang__ && __clang_major__ <= 14
  const char* bls = std::min(i + 1, std::end(Data));
  const char* dbs = std::min(j + 1, std::end(Data));
  const char* fns = std::min(k + 1, std::end(Data));
  typedef std::string_view::size_type sv_size_type;
  const sv_size_type i2j = std::distance(bls, j);
  const sv_size_type j2k = std::distance(dbs, k);
  const sv_size_type k2e = std::distance(fns, std::end(Data));
  Block = {bls, i2j};
  DoubleBlock = {dbs, j2k};
  Filename = {fns, k2e};
// C++20: #else
// C++20: Block = {std::min(i + 1, std::end(Data)), j};
// C++20: DoubleBlock = {std::min(j + 1, std::end(Data)), k};
// C++20: Filename = {std::min(k + 1, std::end(Data)), std::end(Data)};
// C++20: #endif
}

std::string FuzzyHash::hash() const {
  return std::string(Data);
}

uint64_t FuzzyHash::blocksize() const {
  return std::strtoull(Data.data(), nullptr, 10);
}

std::string FuzzyHash::block() const {
  return std::string(Block);
}

std::string FuzzyHash::double_block() const {
  return std::string(DoubleBlock);
}

std::string replaceAll(
  std::string_view s,
  const char* match,
  const char* repl)
{
  const auto match_len = std::strlen(match);
  std::string result;

  auto i = std::string_view::size_type(0);
  do {
    auto j = s.find(match, i);
    if (j == s.npos) {
      result.append(s, i);
      i = s.npos;
    }
    else {
      result.append(s, i, j - i);
      result.append(repl);
      i = j + match_len;
    }
  } while (i != s.npos);

  return result;
}

std::string FuzzyHash::filename() const {
  if (Filename.empty()) {
    return "";
  }
  else {
    // strip leading and trailing double quotes
// C++20: const auto pos = Filename.starts_with('"') ? 1 : 0;
    const auto pos = Filename.front() == '"' ? 1 : 0;
// C++20: const auto len = Filename.size() - (Filename.ends_with('"') ? 1 : 0) - pos;
    const auto len = Filename.size() - (Filename.back() == '"' ? 1 : 0) - pos;
    // unguard the remaining double quotes
    return replaceAll(Filename.substr(pos, len), "\\\"", "\"");
  }
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

    if (!validate_hash(l->first, l->second)) {
      continue;
    }
    const size_t idx = blocksize_index(hash.blocksize());
    map[idx] += std::max((int)hash.block().length() - 6, 1);
    map[idx + 1] += std::max((int)hash.double_block().length() - 6, 1);
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
    // A factor of 2 is probably on the conservative side (i.e., will underestimate the amount of
    // space needed) for a typical (?) data set
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
  return std::make_unique<FuzzyResult>(hash.filename(), std::move(matches));
}

void SFHASH_FuzzyMatcher::add(uint64_t blocksize,
                              std::unordered_set<uint64_t>&& chunks,
                              uint32_t hash_id) {
  for (uint64_t chunk: chunks) {
    ChunkMaps[blocksize_index(blocksize)][chunk].push_back(hash_id);
  }
}

void FuzzyMatcher::lookup_clusters(uint64_t blocksize,
                                   const std::unordered_set<uint64_t>& it,
                                   std::unordered_set<uint32_t>& candidates) const {

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

FuzzyResult::SFHASH_FuzzyResult(std::string&& queryFilename,
                                std::vector<std::pair<std::string, int>>&& matches):
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

bool validate_hash(const char* beg, const char* end) {
  // blocksize:hash1:hash2,"filename"
  const char* i = std::find(beg, end, ':');
  if (i == end) {
    return false;
  }

  const char* j = std::find(i + 1, end, ':');
  if (j == end) {
    return false;
  }

  const char* k = std::find(j + 1, end, ',');
  if (k == end || k[1] != '"' || end[-1] != '"') {
    return false;
  }

  try {
    boost::lexical_cast<uint64_t>(beg, i - beg);
  }
  catch (const boost::bad_lexical_cast&) {
    return false;
  }

  return true;
}

uint64_t decode_base64(std::string_view s) {
  using base64_iterator = boost::archive::iterators::transform_width<
    boost::archive::iterators::binary_from_base64<std::string_view::iterator>,
    8,
    6
  >;
  uint64_t val = 0;
  const std::string decoded(base64_iterator(s.begin()), base64_iterator(s.end()));
  std::memcpy(&val, decoded.c_str(), decoded.length());
  return val;
}

std::string removeDuplicates(std::string_view s) {
  std::string rtn(s.substr(0, 3));
  for (size_t i = 3; i < s.length(); ++i) {
    if (s[i] != s[i - 1] || s[i] != s[i - 2] || s[i] != s[i - 3]) {
      rtn.push_back(s[i]);
    }
  }
  return rtn;
}

std::unordered_set<uint64_t> decode_chunks(std::string_view s) {
  // Get all of the 7-grams from the hash string,
  // base64 decode and reinterpret as (6-byte) integer
  if (s.length() == 0) {
    return {0};
  }

  std::string t(removeDuplicates(s));
  if (t.length() < 7) {
    // Pad to 6 characters
    std::string block(std::move(t));
    block.append(6 - block.length(), '=');
    return {decode_base64(block)};
  }

  std::string_view tv(t);
  std::unordered_set<uint64_t> results;
  for (size_t i = 0; i + 7 <= tv.length(); ++i) {
    results.insert(decode_base64(tv.substr(i, 7)));
  }
  return results;
}

std::unique_ptr<SFHASH_FuzzyMatcher, void (*)(SFHASH_FuzzyMatcher*)> load_fuzzy_hashset(const char* beg, const char* end) {
  LineIterator l(beg, end);
  const LineIterator lend(end, end);
  if (l == lend) {
    return {nullptr, nullptr};
  }

  const std::string_view firstLine(l->first, l->second - l->first);
  if (firstLine != "ssdeep,1.1--blocksize:hash:hash,filename") {
    return {nullptr, nullptr};
  }

  auto matcher = make_unique_del(
    new FuzzyMatcher,
    sfhash_destroy_fuzzy_matcher
  );
  matcher->reserve_space(beg, end);

  int lineno = 2;
  for (++l; l != lend; ++l, ++lineno) {
    // skip empty lines
    if (l->first == l->second) {
      continue;
    }

    if (!validate_hash(l->first, l->second)) {
      return {nullptr, nullptr};
    }

    matcher->add(FuzzyHash{l->first, l->second});
  }
  return matcher;
}
