# pragma once

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sparsepp/spp.h>

#include "hasher.h"

class FuzzyHash {
public:

  FuzzyHash(const char* a, const char* b);
  std::string hash() const;

  uint64_t blocksize() const;
  std::string block() const;
  std::string double_block() const;
  std::string filename() const;

  std::unordered_set<uint64_t> chunks() const;
  std::unordered_set<uint64_t> double_chunks() const;

private:
  const char *Beg, *End;
};

class SFHASH_FuzzyMatcher {
public:
  void reserve_space(const char* beg, const char* end);
  void add(FuzzyHash&& hash);
  std::unique_ptr<SFHASH_FuzzyResult> match(const char* beg, const char* end) const;

private:
  void add(uint64_t blocksize, std::unordered_set<uint64_t>&& chunks, uint32_t hash_id);
  void lookup_clusters(uint64_t blocksize, const std::unordered_set<uint64_t>& it, std::unordered_set<uint32_t>& candidates) const;

  std::vector<FuzzyHash> Hashes;
  // blocksize -> (hash_substring_int -> hash_index)
  std::vector<spp::sparse_hash_map<uint64_t, std::vector<uint32_t>>> ChunkMaps;
};

class SFHASH_FuzzyResult {
public:
  SFHASH_FuzzyResult(FuzzyHash&& query, const std::vector<FuzzyHash>* hashes);

  size_t count() const;
  const char* queryFilename() const;
  const char* filename(size_t i) const;
  int score(size_t i) const;

  std::vector<std::pair<uint32_t, int>> Matches;
  const FuzzyHash Query;

private:
  const std::vector<FuzzyHash>* Hashes;
};

int validate_hash(const char* a, const char* b);

std::unordered_set<uint64_t> decode_chunks(const std::string& s);

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end);
