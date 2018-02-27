#include "hasher.h"
#include "fuzzy_matcher.h"

#include <boost/lexical_cast.hpp>
#include <fuzzy.h>

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
      for (auto& candidate: cluster_search->second) {
        max = std::max(max, fuzzy_compare(candidate->hash.c_str(), sig));
      }
    }
  }
  return max;

}

int sfhash_fuzzy_matcher_compare(FuzzyMatcher* matcher, const char* sig) {
  std::unique_ptr<FuzzyHash> hash = parse_sig(sig);

  auto search = matcher->db.find(hash->blocksize);
  if (search == matcher->db.end()) {
    return 0;
  }
  auto chunk_map = search->second;
  int max = 0;
  max = std::max(max, lookup_clusters(matcher, hash->blocksize, hash->get_iterator(), sig));
  max = std::max(max, lookup_clusters(matcher, 2 * hash->blocksize, hash->get_double_iterator(), sig));
  return max;
}

std::unique_ptr<SFHASH_FuzzyMatcher> load_fuzzy_hashset(const char* beg, const char* end) {
  return nullptr;
}

FuzzyMatcher* sfhash_create_fuzzy_matcher(const char* beg, const char* end) {
  return load_fuzzy_hashset(beg, end).release();
}

void sfhash_destroy_fuzzy_matcher(FuzzyMatcher* matcher) {
  delete matcher;
}

std::unique_ptr<FuzzyHash> parse_sig(const char * sig) {
  // blocksize:hash1:hash2,"filename"
  std::string s(sig);

  auto i1 = s.find_first_of(':', 0);
  if (i1 == std::string::npos) {
    return nullptr;
  }

  auto i2 = s.find_first_of(':', i1 + 1);
  if (i2 == std::string::npos) {
    return nullptr;
  }

  std::string filename = "";
  auto i3 = s.find_first_of(',', i2 + 1);
  if (i3 == std::string::npos) {
    i3 = s.length();
  }
  else {
    filename = s.substr(i3 + 2, s.length() - i3 - 3);
    while (filename.find("\\\"") != std::string::npos) {
      filename.replace(filename.find("\\\""), 2, "\"");
    }
  }

  if (s[i3+1] != '"' ||  s[s.size() -1] != '"') {
    return nullptr;
  }

  uint64_t blocksize;

  try {
    blocksize = boost::lexical_cast<uint64_t>(s.substr(0, i1));
  } catch(boost::bad_lexical_cast) {
    return nullptr;
  }
  return std::unique_ptr<FuzzyHash>(new FuzzyHash{blocksize, s, s.substr(i1+1, i2 - i1 - 1), s.substr(i2+1, i3 - i2 - 1), filename});
}

std::vector<uint64_t> FuzzyHash::get_iterator() {
  return std::vector<uint64_t>();
}

std::vector<uint64_t> FuzzyHash::get_double_iterator() {
  return std::vector<uint64_t>();
}
