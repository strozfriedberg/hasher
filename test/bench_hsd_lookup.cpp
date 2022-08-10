#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <ostream>
#include <random>
#include <string>
#include <sstream>
#include <vector>

#include "hasher/api.h"

#include "hashsetdata.h"
#include "hashsetinfo.h"
#include "hex.h"
#include "throw.h"
#include "util.h"

const std::filesystem::path VS{"test/virusshare-389.hset"};
const size_t VS_HLEN = 16;

const std::filesystem::path NSRL{"test/nsrl_rds_2.71_asdf_hashes.hset"};
const size_t NSRL_HLEN = 20;

// interface for the raw hashset data
struct Holder {
  virtual ~Holder() = default;

  void* beg;
  void* end;
};

// holds raw hashset data in memory
struct MemoryHolder: public Holder {
  MemoryHolder(std::vector<char>&& the_buf): buf(std::move(the_buf)) {
    beg = buf.data();
    end = buf.data() + buf.size();
  }

  std::vector<char> buf;
};

// read a file into memory
MemoryHolder read_file(const std::filesystem::path& p) {
  const size_t fsize = std::filesystem::file_size(p);

  std::ifstream in(p, std::ios::binary);
  in.exceptions(in.failbit);

  std::vector<char> buf(fsize);
  in.read(buf.data(), fsize);

  return MemoryHolder(std::move(buf));
}

// get the hashset header
auto load_header(void *beg, void* end) {
  SFHASH_Error* err = nullptr;

  auto hsinfo = make_unique_del(
    sfhash_load_hashset_info(beg, end, &err),
    sfhash_destroy_hashset_info
  );

  THROW_IF(err, err->message);
  THROW_IF(!hsinfo, "!hsinfo");

  return hsinfo;
}

struct RNG {
  std::mt19937 re{std::random_device{}()};
  std::uniform_int_distribution<uint32_t> dist;

  uint32_t operator()() {
    return dist(re);
  }
};

// generate some random hashes
template <
  size_t HashLength
>
auto make_random_hashes(RNG& rng, size_t count) {
  std::vector<std::array<uint8_t, HashLength>> hashes(count);

  for (auto& h: hashes) {
    // there should be a better way to do this; relies on all hash lengths
    // being multiples of 4
    for (int i = 0; i < static_cast<int>(HashLength / sizeof(uint32_t)); ++i) {
      *reinterpret_cast<uint32_t*>(&h[i*sizeof(uint32_t)]) = rng();
    }
  }

  return hashes;
}

// sample some hashes from hashset data
template <
  size_t HashLength,
  class Generator,
  class Holder
>
auto sample_hashes(Generator& gen, const Holder& h, size_t count) {
  std::vector<std::array<uint8_t, HashLength>> hashes;
  std::sample(
    static_cast<const std::array<uint8_t, HashLength>*>(h.beg),
    static_cast<const std::array<uint8_t, HashLength>*>(h.end),
    std::back_inserter(hashes),
    count,
    gen
  );
  return hashes;
}

// make a HashSetDataImpl from hashset data 
template <
  size_t HashLength,
  class Holder
>
auto make_std_hsd(Holder& h, const SFHASH_HashSetInfo& hsinfo) {
  return std::unique_ptr<HashSetData>{
    std::make_unique<HashSetDataImpl<HashLength>>(
      static_cast<const char*>(h.beg) + hsinfo.hashset_off,
      static_cast<const char*>(h.beg) + hsinfo.hashset_off + hsinfo.hashset_size * hsinfo.hash_length
    )
  };
}

// make a HashSetDataRadiusImpl from hashset data 
template <
  size_t HashLength,
  class Holder
>
auto make_radius_hsd(Holder& h, const SFHASH_HashSetInfo& hsinfo) {
  return std::unique_ptr<HashSetData>{
    std::make_unique<HashSetDataRadiusImpl<HashLength>>(
      static_cast<const char*>(h.beg) + hsinfo.hashset_off,
      static_cast<const char*>(h.beg) + hsinfo.hashset_off + hsinfo.hashset_size * hsinfo.hash_length,
      hsinfo.radius
    )
  };
}

template <
  class LookupList
>
bool lookup_func(const HashSetData& hsd, const LookupList& hashes) {
  bool r = false;
  for (const auto& h: hashes) {
    // XOR is sensitive to all inputs, so cannot be optimized out
    r ^= hsd.contains(h.data());
  }
  return r;
}

template <
  class LookupList
>
void do_check(const std::string& name, const HashSetData& hsd, const LookupList& hashes) {
  const std::string tag = std::to_string(hashes[0].size()) + " x " + std::to_string(hashes.size());

  BENCHMARK(tag + " " + name) {
    return lookup_func(hsd, hashes);
  };
}

template <
  class LookupList,
  class SetList
>
void do_some_lookups(const LookupList& ll, const SetList& sets) {
  for (const auto& [name, hs]: sets) {
    do_check(name, *hs, ll);
  }
}

template <
  class HashGenerator,
  class SetList
>
void do_some_lookups(HashGenerator& gen, const SetList& sets, size_t min, size_t max, size_t mult) {
  for (size_t i = min; i <= max; i *= mult) {
    do_some_lookups(gen(i), sets);
  }
}

template <
  size_t HashLength,
  class Holder,
  class SetList
>
void do_benchmark(const Holder& h, const SetList& hsds) {
  RNG rng;
  auto gen = [&rng](size_t count) {
    return make_random_hashes<HashLength>(rng, count);
  };

  do_some_lookups(gen, hsds, 1, 100000, 10);
}

// check that all results for the given hash match
template <
  class Hash
>
bool check_agreement(const Hash& h, const std::vector<bool>& hits, std::ostream& out) {

  const bool ok = std::find(hits.begin() + 1, hits.end(), !hits[0]) == hits.end();
/*
  if (!ok) {
    std::ostringstream ss;
    ss << to_hex(h) << ": ";
    for (auto b: hits) {
      ss << b;
    }
    FAIL(ss.str());
  }
*/

  out << to_hex(h) << ": ";
  for (auto b: hits) {
    out << b;
  }
  out << '\n';

  return ok;
}

template <
  class LookupList,
  class SetList
>
bool check_agreement(const LookupList& lookups, const SetList& hsds, std::ostream& out) {
  bool ok = true;
  std::vector<bool> hits(hsds.size());
  for (const auto& h: lookups) {
    for (size_t i = 0; i < hsds.size(); ++i) {
      hits[i] = hsds[i].second->contains(h.data());
    }
    ok &= check_agreement(h, hits, out);
  }
  return ok;
}

template <
  size_t HashLength,
  class Holder,
  class SetList
>
void do_agreement_check(const Holder& h, const SetList& hsds) {
  // lookup some random hashes
  RNG rng;
  auto gen = [&rng](size_t count) {
    return make_random_hashes<HashLength>(rng, count);
  };

  bool ok = true;
  std::ostringstream ss;

  const auto lookup_random = gen(1000);
  ok &= check_agreement(lookup_random, hsds, ss);

  // lookup some randomly sampled hashes
  const auto lookup_sample = sample_hashes<HashLength>(rng.re, h, 1000);
  ok &= check_agreement(lookup_sample, hsds, ss);

  if (!ok) {
    FAIL(ss.str());
  }
}

template <
  size_t HashLength,
  class Holder
>
auto make_hsds(const Holder& h) {
  const auto hsinfo = load_header(h.beg, h.end);
  REQUIRE(hsinfo->hash_length == HashLength);

  std::vector<std::pair<std::string, std::unique_ptr<HashSetData>>> hsds;
// TODO: why can't these go into an intializer list?
  hsds.emplace_back("std", make_std_hsd<HashLength>(h, *hsinfo));
  hsds.emplace_back("radius", make_radius_hsd<HashLength>(h, *hsinfo));

  return hsds;
}

TEST_CASE("MemoryLookupCheckVirusShare") {
  MemoryHolder h{read_file(VS)};
  const auto hsds = make_hsds<VS_HLEN>(h);
  do_agreement_check<VS_HLEN>(h, hsds);
}

TEST_CASE("MemoryLookupCheckNSRL") {
  MemoryHolder h{read_file(NSRL)};
  const auto hsds = make_hsds<NSRL_HLEN>(h);
  do_agreement_check<NSRL_HLEN>(h, hsds);
}
