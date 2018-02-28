#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include <sys/stat.h>

#include <boost/filesystem.hpp>

#include "config.h"
#include "hasher.h"
#include "throw.h"
#include "util.h"

namespace fs = boost::filesystem;


int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: fuzzy HASHSET TARGETDIR\n"
              << std::endl;
    return -1;
  }

  try {
    std::unique_ptr<SFHASH_FuzzyMatcher, void(*)(SFHASH_FuzzyMatcher*)> mptr{
      nullptr, sfhash_destroy_fuzzy_matcher
    };

    // make a matcher
    {
      // read the hashset file
      std::ifstream in(argv[1], std::ios::binary);
      in.exceptions(std::ifstream::failbit | std::ifstream::badbit);
      const std::string hset((std::istreambuf_iterator<char>(in)),
                             (std::istreambuf_iterator<char>()));
      in.close();

      // create the matcher
      mptr = make_unique_del(
        sfhash_create_fuzzy_matcher(hset.c_str(), hset.c_str() + hset.length()),
        sfhash_destroy_fuzzy_matcher
      );
    }

    SFHASH_FuzzyMatcher* matcher = mptr.get();

    // make a hasher
    std::unique_ptr<SFHASH_Hasher, void(*)(SFHASH_Hasher*)> hptr{
      sfhash_create_hasher(FUZZY),
      sfhash_destroy_hasher
    };

    SFHASH_Hasher* hasher = hptr.get();
    char buf[1024*1024];
    SFHASH_HashValues hashes;

    // walk the tree
    const fs::recursive_directory_iterator end;
    for (fs::recursive_directory_iterator d(argv[2]); d != end; ++d) {
      const fs::path p(d->path());
      if (!fs::is_directory(p)) {
        const std::string n = p.string();

        try {
          sfhash_reset_hasher(hasher);

          std::ifstream f;
          f.exceptions(std::ifstream::badbit);
          f.rdbuf()->pubsetbuf(0, 0); // unbuffered
          f.open(n, std::ios_base::in | std::ios_base::binary);
          do {
            f.read(buf, sizeof(buf));
            sfhash_update_hasher(hasher, buf, buf + f.gcount());
          } while (f);

          sfhash_get_hashes(hasher, &hashes);
          int hmatch = sfhash_fuzzy_matcher_compare(matcher, reinterpret_cast<char*>(hashes.fuzzy));
          if (hmatch > 0) {
            std::cout << "Found fuzzy match for: " << n << ", confidence=" << hmatch << "." << std::endl;
          }
        }
        catch (const fs::filesystem_error& e) {
          std::cerr << "Error: " << p << ": " << e.what() << std::endl;
        }
        catch (const std::runtime_error& e) {
          std::cerr << "Error: " << p << ": " << e.what() << std::endl;
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
