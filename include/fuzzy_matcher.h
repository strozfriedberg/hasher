
# pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "hasher.h"

struct FuzzyHash {
  uint64_t blocksize;
  std::string hash;
  std::string s1, s2;
  std::string filename = "";

  std::vector<uint64_t> get_iterator();
  std::vector<uint64_t> get_double_iterator();
};

struct SFHASH_FuzzyMatcher {
  // blocksize -> (hash_substring_int -> hash)
  int threshold;
  std::vector<FuzzyHash> hashes;
  std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::vector<FuzzyHash*>>> db;

};

std::unique_ptr<FuzzyHash> parse_sig(const char* sig);

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end);
