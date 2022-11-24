#pragma once

#include <concepts>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <ostream>
#include <span>

#include <iostream>

#include "hex.h"

template <class Reference>
struct ArrowProxy {
  Reference r;

  Reference* operator->() {
    return &r;
  }
};

struct RecordProxy {
  std::span<uint8_t> rec;
  std::unique_ptr<uint8_t[]> tmp;

  RecordProxy(std::span<uint8_t> rec): rec(rec) {
//    std::cerr << "RecordProxy(std::span) " << to_hex(rec) << '\n';
  }

  RecordProxy(const RecordProxy& o): rec(o.rec) {
//    std::cerr << "RecordProxy(const RecordProxy&) " << to_hex(o.rec) << '\n';
  }

  RecordProxy& operator=(const RecordProxy& o) noexcept {
//    std::cerr << "RecordProxy::operator=(const RecordProxy&) " << to_hex(rec) << " <= " << to_hex(o.rec) << '\n';
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    return *this;
  }

  RecordProxy(RecordProxy&& o) noexcept {
//    std::cerr << "RecordProxy(RecordProxy&&) " << to_hex(o.rec) << '\n';

    tmp.reset(new uint8_t[o.rec.size()]);
    std::memcpy(tmp.get(), o.rec.data(), o.rec.size());
    rec = { tmp.get(), o.rec.size() };
  }

  RecordProxy& operator=(RecordProxy&& o) noexcept {
//    std::cerr << "RecordProxy::operator=(RecordProxy&&) " << to_hex(rec) << " <= " << to_hex(o.rec) << '\n';
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    return *this;
  }

  auto operator<=>(const RecordProxy& o) const noexcept {
    return std::memcmp(rec.data(), o.rec.data(), rec.size());
  }

  bool operator==(const RecordProxy& o) const noexcept {
    return (*this <=> o) == 0;
  }
};

std::ostream& operator<<(std::ostream& out, const RecordProxy& r);

void swap(RecordProxy a, RecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);

namespace std {
void swap(RecordProxy a, RecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);
}

static_assert(std::swappable<RecordProxy>);

class RecordIterator {
public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = RecordProxy;
  using reference = RecordProxy;
  using pointer = ArrowProxy<reference>;
  using difference_type = std::ptrdiff_t;

  RecordIterator(
    uint8_t* cur,
    uint64_t record_length
  ):
    cur(cur), record_length(record_length)
  {}

  RecordIterator():
    cur(nullptr), record_length(0)
  {}

  reference operator*() const noexcept {
    return reference{{cur, record_length}};
  }

  pointer operator->() const noexcept {
    return pointer{{{cur, record_length}}};
  }

  RecordIterator& operator++() noexcept {
    cur += record_length;
    return *this;
  }

  RecordIterator operator++(int) noexcept {
    RecordIterator itr{*this};
    ++(*this);
    return itr;
  }

  RecordIterator& operator--() noexcept {
    cur -= record_length;
    return *this;
  }

  RecordIterator operator--(int) noexcept {
    RecordIterator itr{*this};
    --(*this);
    return itr;
  }

  RecordIterator operator+(difference_type n) const noexcept {
    RecordIterator itr{*this};
    return itr += n;
  }

  friend RecordIterator operator+(difference_type n, const RecordIterator& i) noexcept {
    return i + n;
  }

  RecordIterator operator-(difference_type n) const noexcept {
    RecordIterator itr{*this};
    return itr -= n;
  }

  difference_type operator-(const RecordIterator& o) const noexcept {
    return (cur - o.cur) / record_length;
  }

  RecordIterator& operator+=(difference_type n) noexcept {
    cur += n * record_length;
    return *this;
  }

  RecordIterator& operator-=(difference_type n) noexcept {
    cur -= n * record_length;
    return *this;
  }

  reference operator[](difference_type n) const noexcept {
    return *(*this + n);
  }

  auto operator<=>(const RecordIterator& o) const noexcept {
    return cur - o.cur;
  }

  bool operator==(const RecordIterator& o) const noexcept {
    return cur == o.cur;
  }

  friend std::ostream& operator<<(std::ostream& out, const RecordIterator& i);

private:
  uint8_t* cur;
  uint64_t record_length;
};

static_assert(std::random_access_iterator<RecordIterator>);

struct HashRecordProxy {
  std::span<uint8_t> rec;
  uint64_t* idx;

  std::unique_ptr<uint8_t[]> tmp;
  uint64_t tmp_idx;

  HashRecordProxy(std::span<uint8_t> rec, uint64_t* idx): rec(rec), idx(idx) {
//    std::cerr << "RecordProxy(std::span) " << to_hex(rec) << '\n';
  }

  HashRecordProxy(const HashRecordProxy& o): rec(o.rec), idx(o.idx) {
//    std::cerr << "RecordProxy(const RecordProxy&) " << to_hex(o.rec) << '\n';
  }

  HashRecordProxy& operator=(const HashRecordProxy& o) noexcept {
//    std::cerr << "RecordProxy::operator=(const RecordProxy&) " << to_hex(rec) << " <= " << to_hex(o.rec) << '\n';
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    *idx = *(o.idx);
    return *this;
  }

  HashRecordProxy(HashRecordProxy&& o) noexcept {
//    std::cerr << "RecordProxy(RecordProxy&&) " << to_hex(o.rec) << '\n';

    tmp.reset(new uint8_t[o.rec.size()]);
    std::memcpy(tmp.get(), o.rec.data(), o.rec.size());
    rec = { tmp.get(), o.rec.size() };

    tmp_idx = *(o.idx);
    idx = &tmp_idx;
  }

  HashRecordProxy& operator=(HashRecordProxy&& o) noexcept {
//    std::cerr << "RecordProxy::operator=(RecordProxy&&) " << to_hex(rec) << " <= " << to_hex(o.rec) << '\n';
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    *idx = *(o.idx);
    return *this;
  }

  auto operator<=>(const HashRecordProxy& o) const noexcept {
    const auto r = std::memcmp(rec.data(), o.rec.data(), rec.size());
    return r == 0 ? *(o.idx) - *idx : r;
  }

  bool operator==(const HashRecordProxy& o) const noexcept {
    return (*this <=> o) == 0;
  }
};

std::ostream& operator<<(std::ostream& out, const HashRecordProxy& r);

void swap(HashRecordProxy a, HashRecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);

namespace std {
void swap(HashRecordProxy a, HashRecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);
}


class HashRecordIterator {
public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = HashRecordProxy;
  using reference = HashRecordProxy;
  using pointer = ArrowProxy<reference>;
  using difference_type = std::ptrdiff_t;

  HashRecordIterator(
    size_t pos,
    uint8_t* hashes,
    uint64_t record_length,
    uint64_t* indices
  ):
    pos(pos), hashes(hashes), record_length(record_length), indices(indices)
  {}

  HashRecordIterator():
    pos(0), hashes(nullptr), record_length(0), indices(nullptr)
  {}

  reference operator*() const noexcept {
    return reference{{hashes + pos * record_length, record_length}, indices + pos};
  }

  pointer operator->() const noexcept {
    return pointer{{{hashes + pos * record_length, record_length}, indices + pos}};
  }

  HashRecordIterator& operator++() noexcept {
    ++pos;
    return *this;
  }

  HashRecordIterator operator++(int) noexcept {
    HashRecordIterator itr{*this};
    ++(*this);
    return itr;
  }

  HashRecordIterator& operator--() noexcept {
    --pos;
    return *this;
  }

  HashRecordIterator operator--(int) noexcept {
    HashRecordIterator itr{*this};
    --(*this);
    return itr;
  }

  HashRecordIterator operator+(difference_type n) const noexcept {
    HashRecordIterator itr{*this};
    return itr += n;
  }

  friend HashRecordIterator operator+(difference_type n, const HashRecordIterator& i) noexcept {
    return i + n;
  }

  HashRecordIterator operator-(difference_type n) const noexcept {
    HashRecordIterator itr{*this};
    return itr -= n;
  }

  difference_type operator-(const HashRecordIterator& o) const noexcept {
    return difference_type(pos) - difference_type(o.pos);
  }

  HashRecordIterator& operator+=(difference_type n) noexcept {
    pos += n;
    return *this;
  }

  HashRecordIterator& operator-=(difference_type n) noexcept {
    pos -= n;
    return *this;
  }

  reference operator[](difference_type n) const noexcept {
    return *(*this + n);
  }

  auto operator<=>(const HashRecordIterator& o) const noexcept {
    return pos - o.pos;
  }

  bool operator==(const HashRecordIterator& o) const noexcept {
    return pos == o.pos;
  }

private:
  size_t pos;
  uint8_t* hashes;
  uint64_t record_length;
  uint64_t* indices;
};

static_assert(std::random_access_iterator<HashRecordIterator>);
