#include "hasher/api.h"
#include "hashset.h"
#include "hashsetdata.h"
#include "hashsetinfo.h"
#include "hex.h"
#include "util.h"

#include <algorithm>
#include <iostream>

#include <scope/test.h>

size_t union_max_size(const SFHASH_HashSet& a, const SFHASH_HashSet& b) {
  return HASHSET_OFF + a.info->hashset_size * a.info->hash_length +
                       b.info->hashset_size * b.info->hash_length;
}

size_t intersection_max_size(const SFHASH_HashSet& a, const SFHASH_HashSet& b) {
  return HASHSET_OFF +
    std::max(a.info->hashset_size, b.info->hashset_size) * a.info->hash_length;
}

size_t difference_max_size(const SFHASH_HashSet& a, const SFHASH_HashSet&) {
  return HASHSET_OFF + a.info->hashset_size * a.info->hash_length;
}

const std::vector<std::array<uint8_t, 16>> MD5s{
  to_bytes<16>("0cd9677a02aa28cd16c83a8ff7645302"),
  to_bytes<16>("14d3ddf66aae1135a60a8b0add939c77"),
  to_bytes<16>("25eb370e9e373d5647000f3ceadaa3f7"),
  to_bytes<16>("2ffc23465adab853db98cbf2aa6c8a6a"),
  to_bytes<16>("3cadb2eeba56ff66ddbb69eb3b28819f"),
  to_bytes<16>("3dd5356b0d2fae1177960ff8a50eeb7e"),
  to_bytes<16>("5b8a8a906fd43869a588f72463da1c91"),
  to_bytes<16>("5d0bda1f38b42182fa3e98d5faa70a53"),
  to_bytes<16>("653e6dbe37cbc839ae7db95d6a32b2a9"),
  to_bytes<16>("66c8c42f125d4459307402d48ee4cf5b"),
  to_bytes<16>("69b2af002639834816f83973442fb262"),
  to_bytes<16>("7165157fa9e015324f6a7252c1335220"),
  to_bytes<16>("73c0f4432f5233b3c0b00e51cfa8d414"),
  to_bytes<16>("74674bf586679ab553cb4ba8780fb13d"),
  to_bytes<16>("756daa8c5b6b725201bdd51868cd51f9"),
  to_bytes<16>("76cf86927b17de26082c077d06d9ead7"),
  to_bytes<16>("770210275a270eed54e748d8fca30f54"),
  to_bytes<16>("7d7901ab861e51eeefbef433a0176282"),
  to_bytes<16>("8a491f440eb50c8f954b66e784f897b2"),
  to_bytes<16>("91023a1d58d69b4916a8609882d782a8"),
  to_bytes<16>("9277197b01b73602f29ffdcdebba477c"),
  to_bytes<16>("92b6f4c86322c67b249fe877ae069a0f"),
  to_bytes<16>("bb970079c15d178852d9261b48e2697f"),
  to_bytes<16>("d0a3dc94d3e310b5e95747078b2db63b"),
  to_bytes<16>("e5e8b3de9c0f7d9ba280333b09971643"),
  to_bytes<16>("e8e3e414fee160337703c8dcbee5a2f9")
};

template <size_t HashLength>
void dump_test_hashset(const SFHASH_HashSet& hs) {
  auto h = reinterpret_cast<const std::array<uint8_t, HashLength>*>(
    hs.hset->data()
  );
  for (size_t i = 0; i < hs.info->hashset_size; ++i) {
    std::cout << to_hex(h[i]) << '\n';
  }
  std::cout << '\n';
}

template <size_t HashLength>
auto make_test_hashset(
  const char* name,
  const char* desc,
  SFHASH_HashAlgorithm type,
  const std::array<uint8_t, HashLength>* beg,
  const std::array<uint8_t, HashLength>* end)
{
  SFHASH_Error* err = nullptr;

  auto info = make_info(
      name,
      desc,
      type,
      beg,
      end
  );

  auto hset = make_unique_del(
    sfhash_load_hashset_data(info.get(), beg, end, &err),
    sfhash_destroy_hashset_data
  );

  SCOPE_ASSERT(!err);

  return SFHASH_HashSet{std::move(info), std::move(hset)};
}

SCOPE_TEST(a_union_b_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_MD5, &MD5s[11], &MD5s[26]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + union_max_size(a, b)]};

  const char oname[] = "a u b";
  const char odesc[] = "union of a and b";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_union_hashsets(&a, &b, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(!err);

  // check the header
  SCOPE_ASSERT_EQUAL(1, o->info->version);
  SCOPE_ASSERT_EQUAL(SFHASH_MD5, o->info->hash_type);
  SCOPE_ASSERT_EQUAL(16, o->info->hash_length);
  SCOPE_ASSERT_EQUAL(0, o->info->flags);
  SCOPE_ASSERT_EQUAL(26, o->info->hashset_size);
  SCOPE_ASSERT_EQUAL(HASHSET_OFF, o->info->hashset_off);
  SCOPE_ASSERT_EQUAL(0, o->info->sizes_off);
  SCOPE_ASSERT_EQUAL(7, o->info->radius);
  SCOPE_ASSERT_EQUAL(oname, std::string(o->info->hashset_name));
  SCOPE_ASSERT_EQUAL(odesc, std::string(o->info->hashset_desc));

  // check the hashes
  const auto obeg = reinterpret_cast<const std::array<uint8_t, 16>*>(o->hset->data());
  SCOPE_ASSERT(std::equal(MD5s.begin(), MD5s.end(), obeg, obeg + o->info->hashset_size));
}

SCOPE_TEST(b_union_a_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_MD5, &MD5s[11], &MD5s[26]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + union_max_size(a, b)]};

  const char oname[] = "b u a";
  const char odesc[] = "union of b and a";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_union_hashsets(&b, &a, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(!err);

  // check the header
  SCOPE_ASSERT_EQUAL(1, o->info->version);
  SCOPE_ASSERT_EQUAL(SFHASH_MD5, o->info->hash_type);
  SCOPE_ASSERT_EQUAL(16, o->info->hash_length);
  SCOPE_ASSERT_EQUAL(0, o->info->flags);
  SCOPE_ASSERT_EQUAL(26, o->info->hashset_size);
  SCOPE_ASSERT_EQUAL(HASHSET_OFF, o->info->hashset_off);
  SCOPE_ASSERT_EQUAL(0, o->info->sizes_off);
  SCOPE_ASSERT_EQUAL(7, o->info->radius);
  SCOPE_ASSERT_EQUAL(oname, std::string(o->info->hashset_name));
  SCOPE_ASSERT_EQUAL(odesc, std::string(o->info->hashset_desc));

  // check the hashes
  const auto obeg = reinterpret_cast<const std::array<uint8_t, 16>*>(o->hset->data());
  SCOPE_ASSERT(std::equal(MD5s.begin(), MD5s.end(), obeg, obeg + o->info->hashset_size));
}

SCOPE_TEST(a_intersect_b_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_MD5, &MD5s[11], &MD5s[26]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + intersection_max_size(a, b)]};

  const char oname[] = "a n b";
  const char odesc[] = "intersection of a and b";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_intersect_hashsets(&a, &b, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(!err);

  // check the header
  SCOPE_ASSERT_EQUAL(1, o->info->version);
  SCOPE_ASSERT_EQUAL(SFHASH_MD5, o->info->hash_type);
  SCOPE_ASSERT_EQUAL(16, o->info->hash_length);
  SCOPE_ASSERT_EQUAL(0, o->info->flags);
  SCOPE_ASSERT_EQUAL(7, o->info->hashset_size);
  SCOPE_ASSERT_EQUAL(HASHSET_OFF, o->info->hashset_off);
  SCOPE_ASSERT_EQUAL(0, o->info->sizes_off);
  SCOPE_ASSERT_EQUAL(3, o->info->radius);
  SCOPE_ASSERT_EQUAL(oname, std::string(o->info->hashset_name));
  SCOPE_ASSERT_EQUAL(odesc, std::string(o->info->hashset_desc));

  // check the hashes
  const auto obeg = reinterpret_cast<const std::array<uint8_t, 16>*>(o->hset->data());
  SCOPE_ASSERT(std::equal(&MD5s[11], &MD5s[18], obeg, obeg + o->info->hashset_size));
}

SCOPE_TEST(b_intersect_a_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_MD5, &MD5s[11], &MD5s[26]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + intersection_max_size(a, b)]};

  const char oname[] = "b n a";
  const char odesc[] = "intersection of b and a";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_intersect_hashsets(&b, &a, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(!err);

  // check the header
  SCOPE_ASSERT_EQUAL(1, o->info->version);
  SCOPE_ASSERT_EQUAL(SFHASH_MD5, o->info->hash_type);
  SCOPE_ASSERT_EQUAL(16, o->info->hash_length);
  SCOPE_ASSERT_EQUAL(0, o->info->flags);
  SCOPE_ASSERT_EQUAL(7, o->info->hashset_size);
  SCOPE_ASSERT_EQUAL(HASHSET_OFF, o->info->hashset_off);
  SCOPE_ASSERT_EQUAL(0, o->info->sizes_off);
  SCOPE_ASSERT_EQUAL(3, o->info->radius);
  SCOPE_ASSERT_EQUAL(oname, std::string(o->info->hashset_name));
  SCOPE_ASSERT_EQUAL(odesc, std::string(o->info->hashset_desc));

  // check the hashes
  const auto obeg = reinterpret_cast<const std::array<uint8_t, 16>*>(o->hset->data());
  SCOPE_ASSERT(std::equal(&MD5s[11], &MD5s[18], obeg, obeg + o->info->hashset_size));
}

SCOPE_TEST(a_minus_b_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_MD5, &MD5s[11], &MD5s[26]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + difference_max_size(a, b)]};

  const char oname[] = "a - b";
  const char odesc[] = "a minus b";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_difference_hashsets(&a, &b, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(!err);

  // check the header
  SCOPE_ASSERT_EQUAL(1, o->info->version);
  SCOPE_ASSERT_EQUAL(SFHASH_MD5, o->info->hash_type);
  SCOPE_ASSERT_EQUAL(16, o->info->hash_length);
  SCOPE_ASSERT_EQUAL(0, o->info->flags);
  SCOPE_ASSERT_EQUAL(11, o->info->hashset_size);
  SCOPE_ASSERT_EQUAL(HASHSET_OFF, o->info->hashset_off);
  SCOPE_ASSERT_EQUAL(0, o->info->sizes_off);
  SCOPE_ASSERT_EQUAL(6, o->info->radius);
  SCOPE_ASSERT_EQUAL(oname, std::string(o->info->hashset_name));
  SCOPE_ASSERT_EQUAL(odesc, std::string(o->info->hashset_desc));

  // check the hashes
  const auto obeg = reinterpret_cast<const std::array<uint8_t, 16>*>(o->hset->data());
  SCOPE_ASSERT(std::equal(&MD5s[0], &MD5s[11], obeg, obeg + o->info->hashset_size));
}

SCOPE_TEST(b_minus_a_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_MD5, &MD5s[11], &MD5s[26]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + difference_max_size(a, b)]};

  const char oname[] = "b - a";
  const char odesc[] = "b minus a";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_difference_hashsets(&b, &a, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(!err);

  // check the header
  SCOPE_ASSERT_EQUAL(1, o->info->version);
  SCOPE_ASSERT_EQUAL(SFHASH_MD5, o->info->hash_type);
  SCOPE_ASSERT_EQUAL(16, o->info->hash_length);
  SCOPE_ASSERT_EQUAL(0, o->info->flags);
  SCOPE_ASSERT_EQUAL(8, o->info->hashset_size);
  SCOPE_ASSERT_EQUAL(HASHSET_OFF, o->info->hashset_off);
  SCOPE_ASSERT_EQUAL(0, o->info->sizes_off);
  SCOPE_ASSERT_EQUAL(4, o->info->radius);
  SCOPE_ASSERT_EQUAL(oname, std::string(o->info->hashset_name));
  SCOPE_ASSERT_EQUAL(odesc, std::string(o->info->hashset_desc));

  // check the hashes
  const auto obeg = reinterpret_cast<const std::array<uint8_t, 16>*>(o->hset->data());
  SCOPE_ASSERT(std::equal(&MD5s[18], &MD5s[26], obeg, obeg + o->info->hashset_size));
}

const std::vector<std::array<uint8_t, 20>> SHA1s{
  to_bytes<20>("0cd9677a02aa28cd16c83a8ff7645302ffff0000")
};

SCOPE_TEST(union_type_mismatch_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_SHA_1, &SHA1s[0], &SHA1s[1]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + union_max_size(a, b)]};

  const char oname[] = "a u b";
  const char odesc[] = "union of a and b";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_union_hashsets(&a, &b, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(err);
}

SCOPE_TEST(insersection_type_mismatch_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_SHA_1, &SHA1s[0], &SHA1s[1]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + union_max_size(a, b)]};

  const char oname[] = "a n b";
  const char odesc[] = "intersection of a and b";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_intersect_hashsets(&a, &b, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(err);
}

SCOPE_TEST(difference_type_mismatch_test) {
  const auto a = make_test_hashset("a", "test set a", SFHASH_MD5, &MD5s[0], &MD5s[18]);
  const auto b = make_test_hashset("b", "test set b", SFHASH_SHA_1, &SHA1s[0], &SHA1s[1]);

  std::unique_ptr<uint8_t[]> odata{new uint8_t[HASHSET_OFF + union_max_size(a, b)]};

  const char oname[] = "a - b";
  const char odesc[] = "a minus b";

  SFHASH_Error* err = nullptr;

  auto o = make_unique_del(
    sfhash_intersect_hashsets(&a, &b, odata.get(), oname, odesc, &err),
    sfhash_destroy_hashset
  );

  SCOPE_ASSERT(err);
}
