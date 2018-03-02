#include "hasher.h"
#include "parser.h"
#include "fuzzy_matcher.h"

#include <boost/lexical_cast.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <fuzzy.h>
#include <iostream>

using FuzzyMatcher = SFHASH_FuzzyMatcher;

void FuzzyMatcher::lookup_clusters(
    uint64_t blocksize,
    const std::unordered_set<uint64_t>& it)
{
  auto search = db.find(blocksize);
  if (search == db.end()) {
    return;
  }

  std::unordered_set<FuzzyHash*> candidates;
  for (auto& cluster: it) {
    auto cluster_search = search->second.find(cluster);
    if (cluster_search != search->second.end()) {
      for (FuzzyHash* hash: cluster_search->second) {
        candidates.insert(hash);
      }
    }
  }
  for (FuzzyHash* candidate: candidates) {
    int score = fuzzy_compare(candidate->hash.c_str(), query.hash.c_str());
    if (score > 0) {
      matches.push_back(std::make_pair(candidate, score));
    }
  }

}

SFHASH_FuzzyResult* sfhash_fuzzy_get_match(SFHASH_FuzzyMatcher* matcher, int i) {
  return matcher->get_match(i).release();
}

const char* sfhash_fuzzy_result_filename(SFHASH_FuzzyResult* result) {
  return result->filename.c_str();
}

const char* sfhash_fuzzy_result_query_filename(SFHASH_FuzzyResult* result) {
  return result->query_filename.c_str();
}

int sfhash_fuzzy_result_score(SFHASH_FuzzyResult* result) {
  return result->score;
}

void sfhash_fuzzy_destroy_match(SFHASH_FuzzyResult* result) {
  delete result;
}

std::unique_ptr<SFHASH_FuzzyResult> FuzzyMatcher::get_match(size_t i) {
  return std::unique_ptr<SFHASH_FuzzyResult>(
      new SFHASH_FuzzyResult {
      matches[i].first->filename(),
      query.filename(),
      matches[i].second
  });
}



int FuzzyMatcher::match(const char* sig) {
  query = FuzzyHash(sig);
  auto blocksize = query.blocksize();

  matches.clear();

  lookup_clusters(blocksize, query.chunks());
  lookup_clusters(2 * blocksize, query.double_chunks());

  return matches.size();
}

int sfhash_fuzzy_matcher_compare(FuzzyMatcher* matcher, const char* sig) {
  return matcher->match(sig);
}

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end) {
  std::unique_ptr<FuzzyMatcher> matcher(new FuzzyMatcher);
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

    std::unique_ptr<FuzzyHash> hash(new FuzzyHash(std::string(l->first, l->second - l->first)));
    if (hash->validate()) {
      return nullptr;
    }
    matcher->add(std::move(hash));
  }
  return matcher;
}

void SFHASH_FuzzyMatcher::add(std::unique_ptr<FuzzyHash> hash) {
  FuzzyHash* ptr = hash.get();
  hashes.push_back(std::move(hash));
  add(ptr->blocksize(), ptr->chunks(), ptr);
  add(2 * ptr->blocksize(), ptr->double_chunks(), ptr);
}

void SFHASH_FuzzyMatcher::add(uint64_t blocksize, std::unordered_set<uint64_t> chunks, FuzzyHash* hash) {
  for(uint64_t chunk: chunks) {
    db[blocksize][chunk].push_back(hash);
  }
}

FuzzyMatcher* sfhash_create_fuzzy_matcher(const char* beg, const char* end) {
  return load_fuzzy_hashset(beg, end).release();
}

void sfhash_destroy_fuzzy_matcher(FuzzyMatcher* matcher) {
  delete matcher;
}

int FuzzyHash::validate() {
  // blocksize:hash1:hash2,"filename"
  auto i = hash.find_first_of(':', 0);
  if (i == std::string::npos) {
    return 1;
  }

  auto j = hash.find_first_of(':', i + 1);
  if (j == std::string::npos) {
    return 1;
  }

  auto k = hash.find_first_of(',', j + 1);
  if (hash[k+1] != '"' ||  hash[hash.size() -1] != '"') {
    return 1;
  }


  try {
    boost::lexical_cast<uint64_t>(hash.substr(0, i));
  } catch(boost::bad_lexical_cast) {
    return 1;
  }
  return 0;
}

uint64_t FuzzyHash::blocksize() {
  auto i = hash.find_first_of(':', 0);
  uint64_t blocksize = 0;
  try {

    blocksize = boost::lexical_cast<uint64_t>(hash.substr(0, i));
  } catch(boost::bad_lexical_cast) {}
  return blocksize;

}

std::string FuzzyHash::block() {
  auto i = hash.find_first_of(':', 0);
  auto j = hash.find_first_of(':', i + 1);
  return hash.substr(i + 1, j-i-1);
}

std::string FuzzyHash::double_block() {
  auto i = hash.find_first_of(':', 0);
  auto j = hash.find_first_of(':', i + 1);
  auto k = hash.find_first_of(',', j + 1);
  return hash.substr(j+1, k - j - 1);
}

std::string FuzzyHash::filename() {
  auto i = hash.find_first_of(':', 0);
  auto j = hash.find_first_of(':', i + 1);
  auto k = hash.find_first_of(',', j + 1);
  std::string filename;
  if (k == std::string::npos) {
    filename = "";
  }
  else {
    filename = hash.substr(k + 2, hash.length() - k - 3);
    while (filename.find("\\\"") != std::string::npos) {
      filename.replace(filename.find("\\\""), 2, "\"");
    }
  }
  return filename;
}

std::unordered_set<uint64_t> decode_chunks(const std::string& s) {
  // Get all of the 7-grams from the hash string,
  // base64 decode and reinterpret as (5-byte) integer
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

std::unordered_set<uint64_t> FuzzyHash::chunks() {
  return decode_chunks(block());
}

std::unordered_set<uint64_t> FuzzyHash::double_chunks() {
  return decode_chunks(double_block());
}

FuzzyHash::FuzzyHash(const std::string& sig) :
  hash(sig) {}
