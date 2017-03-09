#include "hasher.h"
#include "util.h"

#include <iostream>

int main(int argc, char** argv) {
  auto hasher = make_unique_del(
    sfhash_create_hasher(MD5 | SHA1 | SHA256),
    sfhash_destroy_hasher
  );

  char buf[4096];
  
  do {
    std::cin.read(buf, sizeof(buf));
    sfhash_update_hasher(hasher.get(), buf, buf + std::cin.gcount());
  } while (std::cin);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  std::cout << to_hex(hashes.md5, hashes.md5+16)
            << '\n' 
            << to_hex(hashes.sha1, hashes.sha1+20)
            << '\n' 
            << to_hex(hashes.sha256, hashes.sha256+32)
            << '\n';

  return 0;
}
