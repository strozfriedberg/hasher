#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include <sys/stat.h>

#include <boost/filesystem.hpp>

#include "hasher.h"
#include "throw.h"
#include "util.h"

namespace fs = boost::filesystem;


int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: matcher HASHSET TARGETDIR\n"
              << "Output: filename\tsize\tSHA1\tatime\tmtime\tctime\tfmatch\thmatch"
              << std::endl;
    return -1;
  }
  
  try {
    std::unique_ptr<SFHASH_FileMatcher, void(*)(SFHASH_FileMatcher*)> mptr{
      nullptr, sfhash_destroy_matcher
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
      LG_Error* err = nullptr;
      mptr = make_unique_del(
        sfhash_create_matcher(hset.c_str(), hset.c_str() + hset.length(), &err),
        sfhash_destroy_matcher
      );
    }

    SFHASH_FileMatcher* matcher = mptr.get();

    // make a hasher
    std::unique_ptr<SFHASH_Hasher, void(*)(SFHASH_Hasher*)> hptr{
      sfhash_create_hasher(SHA1),
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
          // check the filename for a match
          const bool fmatch = sfhash_matcher_has_filename(matcher, n.c_str());

          // check the file size in the hash set
          const uint64_t size = fs::file_size(p);
          const bool smatch = sfhash_matcher_has_size(matcher, size);

          bool hmatch = false;
          if (fmatch || smatch) {
            // we matched the filename or size, so hash the file
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
            hmatch = sfhash_matcher_has_hash(matcher, size, hashes.sha1);
          }

          if (fmatch || hmatch) {
            // we had a match, print something

            struct stat s;
            THROW_IF(
              stat(n.c_str(), &s) == -1,
              "stat failed: " << std::strerror(errno)
            );

            std::cout << n << '\t'
                      << size << '\t'
                      << to_hex(hashes.sha1, hashes.sha1+20) << '\t'
#ifdef _WIN32
                      << s.st_atime << '\t'
                      << s.st_mtime << '\t'
                      << s.st_ctime << '\t'
#else
                      << s.st_atim.tv_sec << '\t'
                      << s.st_mtim.tv_sec << '\t'
                      << s.st_ctim.tv_sec << '\t'
#endif
                      << fmatch << '\t'
                      << hmatch << '\t'
                      << '\n';
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
