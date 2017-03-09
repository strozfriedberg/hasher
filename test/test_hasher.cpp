#include <scope/test.h>

#include "hasher.h"
#include "util.h"

/*
SCOPE_TEST(emptyHash) {
  auto hasher = make_unique_del(
    sfhash_create_hasher(MD5 | SHA1 | SHA256),
    sfhash_destroy_hasher
  );

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);
 
  SCOPE_ASSERT_EQUAL(
    "d41d8cd98f00b204e9800998ecf8427e",
    to_hex(hashes.md5, hashes.md5+16)
  );

  SCOPE_ASSERT_EQUAL(
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    to_hex(hashes.sha1, hashes.sha1+20)
  );

  SCOPE_ASSERT_EQUAL(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    to_hex(hashes.sha256, hashes.sha256+32)
  );
}
*/
