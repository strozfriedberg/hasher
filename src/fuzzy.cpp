#include "hasher.h"
#include "parser.h"
#include "fuzzy_matcher.h"

#include <boost/lexical_cast.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <fuzzy.h>
#include <iostream>

using FuzzyMatcher = SFHASH_FuzzyMatcher;

int lookup_clusters(
    FuzzyMatcher* matcher,
    uint64_t blocksize,
    const std::vector<uint64_t>& it,
    const char* sig)
{
  auto search = matcher->db.find(blocksize);
  if (search == matcher->db.end()) {
    return 0;
  }

  int max = 0;
  for (auto& cluster: it) {
    auto cluster_search = search->second.find(cluster);
    if (cluster_search != search->second.end()) {
      for (ssize_t id: cluster_search->second) {
        max = std::max(max, fuzzy_compare(matcher->hashes[id].hash.c_str(), sig));
      }
    }
  }
  return max;

}

int sfhash_fuzzy_matcher_compare(FuzzyMatcher* matcher, const char* sig) {
  FuzzyHash hash{sig};
  auto blocksize = hash.blocksize();

  int max = 0;
  max = std::max(max, lookup_clusters(matcher, blocksize, hash.chunks(), sig));
  max = std::max(max, lookup_clusters(matcher, 2 * blocksize, hash.double_chunks(), sig));
  return max;
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

    FuzzyHash hash{std::string(l->first, l->second - l->first)};
    if (hash.validate()) {
      return nullptr;
    }
    matcher->add(hash);

  }
  return matcher;
}

void SFHASH_FuzzyMatcher::add(FuzzyHash& hash) {
  hash.id = hashes.size();
  hashes.push_back(hash);
  add(hash.blocksize(), hash.chunks(), hash);
  add(2 * hash.blocksize(), hash.double_chunks(), hash);
}

void SFHASH_FuzzyMatcher::add(uint64_t blocksize, std::vector<uint64_t> chunks, FuzzyHash& hash) {
  auto search = db.find(blocksize);
  if (search != db.end()) {
    auto& chunk_db = search->second;

    for(uint64_t chunk: chunks) {
      auto chunk_search = chunk_db.find(chunk);
      if (chunk_search != chunk_db.end()) {
        chunk_search->second.push_back(hash.id);
      }
      else {
        chunk_db.emplace(chunk, std::vector<ssize_t> { hash.id });
      }
    }
  }
  else {
    std::unordered_map<uint64_t, std::vector<ssize_t>> chunk_db;

    for(uint64_t chunk: chunks) {
      chunk_db.emplace(chunk, std::vector<ssize_t> { hash.id });
    }
    db.emplace(blocksize, chunk_db);
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

std::vector<uint64_t> decode_chunks(const std::string& s) {
  // Get all of the 7-grams from the hash string,
  // base64 decode and reinterpret as (5-byte) integer
  using base64_iterator = boost::archive::iterators::transform_width<
    boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6
  >;

  std::vector<uint64_t> results;
  for (size_t i = 0; i + 7 < s.size(); ++i) {
    std::string sub = s.substr(i, 7);
    std::string decoded(base64_iterator(sub.begin()), base64_iterator(sub.end()));
    // Well, this is ugly
    results.push_back(*reinterpret_cast<const uint64_t*>(("\x00\x00\x00" + decoded).c_str()));
  }
  return results;
}

std::vector<uint64_t> FuzzyHash::chunks() {
  return decode_chunks(block());
}

std::vector<uint64_t> FuzzyHash::double_chunks() {
  return decode_chunks(double_block());
}

FuzzyHash::FuzzyHash(const std::string& sig) :
  hash(sig) {}
