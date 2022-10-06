#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include <sys/stat.h>

#include "hasher/api.h"
#include "hasher/fuzzy.h"

#include "parser.h"
#include "throw.h"
#include "util.h"

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: fuzzy HASHSET TARGETDIR\n"
              << std::endl;
    return -1;
  }

  try {
    std::unique_ptr<SFHASH_FuzzyMatcher, void (*)(SFHASH_FuzzyMatcher*)>
      mptr{nullptr, sfhash_destroy_fuzzy_matcher};

    // make a matcher
    std::string hset;
    {
      // read the hashset file
      std::ifstream in(argv[1], std::ios::binary);
      in.exceptions(std::ifstream::failbit | std::ifstream::badbit);
      hset = std::string((std::istreambuf_iterator<char>(in)), (std::istreambuf_iterator<char>()));
      in.close();

      // create the matcher
      mptr = make_unique_del(
        sfhash_create_fuzzy_matcher(hset.c_str(), hset.c_str() + hset.length()),
        sfhash_destroy_fuzzy_matcher
      );
    }

    SFHASH_FuzzyMatcher* matcher = mptr.get();

    // make a hasher
    auto hptr = make_unique_del(
      sfhash_create_hasher(SFHASH_FUZZY),
      sfhash_destroy_hasher
    );

    {
      std::ifstream in(argv[2], std::ios::binary);
      in.exceptions(std::ifstream::failbit | std::ifstream::badbit);
      const std::string tset((std::istreambuf_iterator<char>(in)),
                             (std::istreambuf_iterator<char>()));
      in.close();
      int lineno = 1;
      const LineIterator lend(tset.c_str() + tset.length(), tset.c_str() + tset.length());
      for (LineIterator l(tset.c_str(), tset.c_str() + tset.length()); l != lend; ++l, ++lineno) {
        std::string line(l->first, l->second - l->first);
        if (lineno == 1) {
          if (line != "ssdeep,1.1--blocksize:hash:hash,filename") {
            std::cerr << "Invalid match file" << std::endl;
            return -1;
          }
          continue;
        }
        // skip empty lines
        if (l->first == l->second) {
          continue;
        }

        auto rptr = make_unique_del(
          sfhash_fuzzy_matcher_compare(matcher, l->first, l->second),
          sfhash_destroy_fuzzy_match
        );

        const char* query_filename = sfhash_fuzzy_result_query_filename(rptr.get());
        for (size_t i = 0; i < sfhash_fuzzy_result_count(rptr.get()); ++i) {
          std::cout << "\"" << query_filename << "\","
                    << "\"" << sfhash_fuzzy_result_filename(rptr.get(), i) << "\","
                    << sfhash_fuzzy_result_score(rptr.get(), i)
                    << "\n";
        }
      }
    }
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
