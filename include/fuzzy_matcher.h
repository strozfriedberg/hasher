
# pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "hasher.h"

struct FuzzyHash {
  ssize_t id = -1;
  std::string hash;

  FuzzyHash(const std::string& sig);
  int validate();
  std::vector<uint64_t> chunks();
  std::vector<uint64_t> double_chunks();
  std::string block();
  std::string double_block();
  std::string filename();
  uint64_t blocksize();
};

struct SFHASH_FuzzyMatcher {
  // blocksize -> (hash_substring_int -> hash)
  int threshold;
  std::vector<FuzzyHash> hashes;
  std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::unordered_set<ssize_t>>> db;

  void add(FuzzyHash& hash);
  int match(const char* sig);
  std::unique_ptr<SFHASH_FuzzyResult> get_match(size_t i);

private:
  std::vector<std::pair<ssize_t, int>> matches;
  FuzzyHash query = FuzzyHash("");
  void add(uint64_t blocksize, std::vector<uint64_t> chunks, FuzzyHash& hash);
  void lookup_clusters(uint64_t blocksize, const std::vector<uint64_t>& it);
};

struct SFHASH_FuzzyResult {
  std::string filename;
  std::string query_filename;
  int score;
};

std::vector<uint64_t> decode_chunks(const std::string& s);

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end);
