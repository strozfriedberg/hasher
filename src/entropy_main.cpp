#include "entropy.h"
#include "throw.h"
#include "util.h"

#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>


int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: entropy PATH\n" << std::endl;
    return -1;
  }

  try {
    auto entropy = make_unique_del(
      sfhash_create_entropy(),
      sfhash_destroy_entropy
    );

    char buf[4096];

    std::ifstream f;
    f.exceptions(std::ifstream::badbit);
    f.rdbuf()->pubsetbuf(0, 0); // unbuffered
    f.open(argv[1], std::ios_base::in | std::ios_base::binary);

    do {
      f.read(buf, sizeof(buf));
      sfhash_update_entropy(entropy.get(), buf, buf + f.gcount());
    } while (f);

    std::cout << std::setprecision(std::numeric_limits<double>::digits10 + 1)
              << std::fixed
              << sfhash_get_entropy(entropy.get()) << '\n';
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
