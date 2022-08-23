#include "hasher/api.h"
#include "hash_types.h"
#include "hex.h"
#include "throw.h"
#include "util.h"

#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>

#include <boost/lexical_cast.hpp>

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: hasher ALGS PATH\n"
              << "ALGS values:\n";

    for (uint32_t i = 1; i; i <<= 1) {
      std::cerr << "  " << i << ' '
                << sfhash_hash_name(static_cast<SFHASH_HashAlgorithm>(i))
                << '\n';
    }
    std::cerr << "Bitwise-OR them for multihashing." << std::endl;
    return -1;
  }

  try {
    const uint32_t algs = boost::lexical_cast<uint32_t>(argv[1]);

    auto hasher = make_unique_del(
      sfhash_create_hasher(algs), sfhash_destroy_hasher
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

    for (uint32_t i = 1; i; i <<= 1) {
      if (!(algs & i)) {
        continue;
      }

      const SFHASH_HashAlgorithm a = static_cast<SFHASH_HashAlgorithm>(i);

      switch (a) {
      case SFHASH_MD5:
      case SFHASH_SHA_1:
      case SFHASH_SHA_2_224:
      case SFHASH_SHA_2_256:
      case SFHASH_SHA_2_384:
      case SFHASH_SHA_2_512:
      case SFHASH_SHA_3_224:
      case SFHASH_SHA_3_256:
      case SFHASH_SHA_3_384:
      case SFHASH_SHA_3_512:
      case SFHASH_QUICK_MD5:
        {
          const size_t off = hash_member_offset(a);
          std::cout << to_hex(
            reinterpret_cast<const char*>(&hashes + off),
            reinterpret_cast<const char*>(&hashes + off + sfhash_hash_length(a))) << '\n';
          break;
        }
      case SFHASH_FUZZY:
        std::cout << reinterpret_cast<const char*>(hashes.Fuzzy) << '\n';
        break;
      case SFHASH_ENTROPY:
        std::cout << std::setprecision(std::numeric_limits<double>::digits10 + 1)
                  << std::fixed
                  << hashes.Entropy << '\n';
        break;
      default:
        // impossible
        break;
      }
    }
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
