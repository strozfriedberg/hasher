#pragma once

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <numeric>
#include <string>

struct Header {
  uint64_t version;
  std::string hash_type;
  uint64_t hash_length;
  uint64_t flags;
  std::string hashset_name;
  uint64_t hashset_size;
  uint64_t radius;
  std::string hashset_desc;
  std::array<uint8_t, 32> hashset_sha256;
};

Header parse_header(const char* beg, const char* end);

class HashSet {
public:
  virtual ~HashSet() {}
 
  virtual const Header& header() const = 0;
 
  virtual void set_data(const void* beg, const void* end, bool shared) = 0;

  virtual bool contains(const uint8_t* hash) const = 0;
};

template <size_t HashLength>
class HashSetImpl: public HashSet {
public:
/*
  HashSetImpl(const Header& header):
    HashesBeg(nullptr, nullptr),
    HashesEnd(nullptr),
    Hdr(header)
  {}
*/

  HashSetImpl(Header&& header):
    HashesBeg(nullptr, nullptr),
    HashesEnd(nullptr),
    Hdr(header)
  {}

  virtual ~HashSetImpl() {}

  void set_data(const void* beg, const void* end, bool shared) {
    auto b = static_cast<std::array<uint8_t, HashLength>*>(const_cast<void*>(beg));
    auto e = static_cast<std::array<uint8_t, HashLength>*>(const_cast<void*>(end));

    if (shared) {
      HashesBeg = {b, [](std::array<uint8_t, HashLength>*){}};
    }
    else {
      HashesBeg = {
        new std::array<uint8_t, HashLength>[e - b],
        [](std::array<uint8_t, HashLength>* h){ delete[] h; }
      };
      std::memcpy(HashesBeg.get(), b, e - b);
    }

    HashesEnd = e;
  }

  virtual const Header& header() const { return Hdr; }

  virtual bool contains(const uint8_t* hash) const {
    return std::binary_search(
      HashesBeg.get(), HashesEnd,
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }

protected:
  std::unique_ptr<std::array<uint8_t, HashLength>[], void(*)(std::array<uint8_t, HashLength>*)> HashesBeg;
  std::array<uint8_t, HashLength>* HashesEnd;
  Header Hdr;
};

uint32_t expected_index(const uint8_t* h, uint32_t set_size);

template <size_t HashLength>
uint32_t compute_radius(
  const std::array<uint8_t, HashLength>* beg,
  const std::array<uint8_t, HashLength>* end
)
{
// FIXME: types
  const uint32_t count = end - beg;
  int64_t max_delta = 0;
  for (ssize_t i = 0; i < count; ++i) {
    max_delta = std::max(max_delta,
                         std::abs(i - expected_index(beg[i].data(), count)));
  }
  return max_delta;
}

// TODO: compute a radius if there's not one; collapse this into the default impl
template <size_t HashLength>
class HashSetRadiusImpl: public HashSetImpl<HashLength> {
public:
/*
  HashSetRadiusImpl(const Header& header):
    HashSetImpl<HashLength>(header)
  {}
*/

  HashSetRadiusImpl(Header&& header):
    HashSetImpl<HashLength>(std::move(header))
  {}

  virtual ~HashSetRadiusImpl() {}

  virtual bool contains(const uint8_t* hash) const override {
    const size_t exp = expected_index(hash, this->HashesEnd - this->HashesBeg.get());
    return std::binary_search(
      std::max(this->HashesBeg.get(), this->HashesBeg.get() + exp - this->Hdr.radius),
      std::min(this->HashesEnd, this->HashesBeg.get() + exp + this->Hdr.radius + 1),
      *reinterpret_cast<const std::array<uint8_t, HashLength>*>(hash)
    );
  }
};
