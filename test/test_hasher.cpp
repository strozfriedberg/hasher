#include <scope/test.h>

#include <iterator>

#include <fuzzy.h>

#include "hasher.h"
#include "util.h"

SCOPE_TEST(emptyHashNoUpdate) {
  auto hasher = make_unique_del(sfhash_create_hasher(MD5 | SHA1 | SHA256 | FUZZY | QUICK_MD5),
                                sfhash_destroy_hasher);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  SCOPE_ASSERT_EQUAL("d41d8cd98f00b204e9800998ecf8427e",
                     to_hex(std::begin(hashes.Md5), std::end(hashes.Md5)));
  SCOPE_ASSERT_EQUAL("d41d8cd98f00b204e9800998ecf8427e",
                     to_hex(std::begin(hashes.QuickMd5), std::end(hashes.QuickMd5)));

  SCOPE_ASSERT_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709",
                     to_hex(std::begin(hashes.Sha1), std::end(hashes.Sha1)));

  SCOPE_ASSERT_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                     to_hex(std::begin(hashes.Sha256), std::end(hashes.Sha256)));

  SCOPE_ASSERT_EQUAL("3::", std::string((const char*)hashes.Fuzzy));
}

SCOPE_TEST(emptyHashEmptyUpdate) {
  auto hasher = make_unique_del(sfhash_create_hasher(MD5 | SHA1 | SHA256 | FUZZY | QUICK_MD5),
                                sfhash_destroy_hasher);

  sfhash_update_hasher(hasher.get(), nullptr, nullptr);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  SCOPE_ASSERT_EQUAL("d41d8cd98f00b204e9800998ecf8427e",
                     to_hex(std::begin(hashes.Md5), std::end(hashes.Md5)));
  SCOPE_ASSERT_EQUAL("d41d8cd98f00b204e9800998ecf8427e",
                     to_hex(std::begin(hashes.QuickMd5), std::end(hashes.QuickMd5)));

  SCOPE_ASSERT_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709",
                     to_hex(std::begin(hashes.Sha1), std::end(hashes.Sha1)));

  SCOPE_ASSERT_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                     to_hex(std::begin(hashes.Sha256), std::end(hashes.Sha256)));

  SCOPE_ASSERT_EQUAL("3::", std::string((const char*)hashes.Fuzzy));
}

SCOPE_TEST(alphabetHash) {
  const char a[] = "abcdefghijklmnopqrstuvwxyz";

  auto hasher = make_unique_del(sfhash_create_hasher(MD5 | SHA1 | SHA256 | FUZZY | QUICK_MD5),
                                sfhash_destroy_hasher);

  sfhash_update_hasher(hasher.get(), a, a + std::strlen(a));

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  SCOPE_ASSERT_EQUAL("c3fcd3d76192e4007dfb496cca67e13b",
                     to_hex(std::begin(hashes.Md5), std::end(hashes.Md5)));
  SCOPE_ASSERT_EQUAL("c3fcd3d76192e4007dfb496cca67e13b",
                     to_hex(std::begin(hashes.QuickMd5), std::end(hashes.QuickMd5)));

  SCOPE_ASSERT_EQUAL("32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
                     to_hex(std::begin(hashes.Sha1), std::end(hashes.Sha1)));

  SCOPE_ASSERT_EQUAL("71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
                     to_hex(std::begin(hashes.Sha256), std::end(hashes.Sha256)));

  SCOPE_ASSERT_EQUAL("3:u+6LO5Sfn:u+6LO5Sfn", std::string((const char*)hashes.Fuzzy));
}

SCOPE_TEST(FUZZY_MAX_LEN_SIZE) {
  SCOPE_ASSERT_EQUAL(FUZZY_MAX_RESULT, sizeof(SFHASH_HashValues::Fuzzy));
}

SCOPE_TEST(QUICK_HASH_STOPS_UPDATING) {
  size_t len = 300;
  auto a     = std::make_unique<char[]>(len);
  std::memset(a.get(), 'z', len);

  auto hasher = make_unique_del(sfhash_create_hasher(MD5 | QUICK_MD5), sfhash_destroy_hasher);

  sfhash_update_hasher(hasher.get(), a.get(), a.get() + len);

  SFHASH_HashValues hashes;
  sfhash_get_hashes(hasher.get(), &hashes);

  SCOPE_ASSERT_EQUAL("62a457719101124d52a9c4fe5211f52a",
                     to_hex(std::begin(hashes.Md5), std::end(hashes.Md5)));
  SCOPE_ASSERT_EQUAL("422e2b4e027b430225b3cff67247be64",
                     to_hex(std::begin(hashes.QuickMd5), std::end(hashes.QuickMd5)));
}
