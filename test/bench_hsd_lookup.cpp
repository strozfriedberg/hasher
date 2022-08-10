#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <random>
#include <vector>

#include "hasher/api.h"

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
