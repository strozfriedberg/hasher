
# pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <sparsepp/spp.h>
#include <vector>

#include "hasher.h"

struct FuzzyHash {
  const char *beg, *end;

  FuzzyHash(const char* a, const char* b) : beg(a), end(b) {}
  std::string get_hash() { return std::string(beg, end-beg); }
  std::unordered_set<uint64_t> chunks();
  std::unordered_set<uint64_t> double_chunks();
  std::string block();
  std::string double_block();
  std::string filename();
  uint64_t blocksize();
};

struct SFHASH_FuzzyMatcher {
  std::vector<FuzzyHash> hashes;
  // blocksize -> (hash_substring_int -> hash_index)
  std::vector<spp::sparse_hash_map<uint64_t, std::vector<uint32_t>>> db;

  void add(FuzzyHash&& hash);
  int match(const char* beg, const char* end);
  std::unique_ptr<SFHASH_FuzzyResult> get_match(size_t i);

private:
  std::vector<std::pair<uint32_t, int>> matches;
  FuzzyHash query = FuzzyHash(nullptr, nullptr);
  void add(uint64_t blocksize, std::unordered_set<uint64_t> chunks, uint32_t hash_id);
  void lookup_clusters(uint64_t blocksize, const std::unordered_set<uint64_t>& it);
};

struct SFHASH_FuzzyResult {
  std::string filename;
  std::string query_filename;
  int score;
};

int validate_hash(const char* a, const char* b);

std::unordered_set<uint64_t> decode_chunks(const std::string& s);

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end);
