#include "hasher.h"
#include "throw.h"
#include "util.h"

#include <exception>
#include <fstream>
#include <iostream>

#include <boost/lexical_cast.hpp>


int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: hasher algs path" << std::endl;
    return -1;
  }

  try {
    const int algs = boost::lexical_cast<int>(argv[1]);

    auto hasher = make_unique_del(
      sfhash_create_hasher(algs),
      sfhash_destroy_hasher
    );

    char buf[4096];

    std::ifstream f;
    f.exceptions(std::ifstream::badbit);
    f.rdbuf()->pubsetbuf(0, 0); // unbuffered
    f.open(argv[2], std::ios_base::in | std::ios_base::binary);

    do {
      f.read(buf, sizeof(buf));
      sfhash_update_hasher(hasher.get(), buf, buf + f.gcount());
    } while (f);

    SFHASH_HashValues hashes;
    sfhash_get_hashes(hasher.get(), &hashes);

    if (algs & MD5) {
      std::cout << to_hex(hashes.md5, hashes.md5+16) << '\n';
    }

    if (algs & SHA1) {
      std::cout << to_hex(hashes.sha1, hashes.sha1+20) << '\n';
    }

    if (algs & SHA256) {
      std::cout << to_hex(hashes.sha256, hashes.sha256+32) << '\n';
    }
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
