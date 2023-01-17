#include "hashset/record_iterator.h"

#include "hex.h"

#include <cstring>
#include <memory>

#include <iostream>

void swap_em(RecordProxy& a, RecordProxy& b) {
//  std::cerr << "swap_em " << to_hex(a.rec) << " <=> " << to_hex(b.rec) << '\n';
  std::unique_ptr<uint8_t[]> tmp(new uint8_t[a.rec.size()]);
  std::memcpy(tmp.get(), a.rec.data(), a.rec.size());
  std::memcpy(a.rec.data(), b.rec.data(), a.rec.size());
  std::memcpy(b.rec.data(), tmp.get(), a.rec.size());
}

void swap(RecordProxy a, RecordProxy b) {
//  std::cerr << "swap(,)\n";
  swap_em(a, b);
}

void swap(RecordProxy& a, RecordProxy& b) {
//  std::cerr << "swap(&,&)\n";
  swap_em(a, b);
}

namespace std {

void swap(RecordProxy a, RecordProxy b) {
//  std::cerr << "std::swap(,)\n";
  swap_em(a, b);
}

void swap(RecordProxy& a, RecordProxy& b) {
//  std::cerr << "std::swap(&,&)\n";
  swap_em(a, b);
}

}

std::ostream& operator<<(std::ostream& out, const RecordProxy& r) {
  return out << to_hex(r.rec);
}

std::ostream& operator<<(std::ostream& out, const RecordIterator& i) {
  return out << '('
             << static_cast<const void*>(i.cur)
             << ','
             << i.record_length
             << ')';
}

void swap_em(HashRecordProxy& a, HashRecordProxy& b) {
//  std::cerr << "swap_em " << to_hex(a.rec) << " <=> " << to_hex(b.rec) << '\n';
  std::unique_ptr<uint8_t[]> tmp(new uint8_t[a.rec.size()]);
  std::memcpy(tmp.get(), a.rec.data(), a.rec.size());
  std::memcpy(a.rec.data(), b.rec.data(), a.rec.size());
  std::memcpy(b.rec.data(), tmp.get(), a.rec.size());
}

void swap(HashRecordProxy a, HashRecordProxy b) {
//  std::cerr << "swap(,)\n";
  swap_em(a, b);
}

void swap(HashRecordProxy& a, HashRecordProxy& b) {
//  std::cerr << "swap(&,&)\n";
  swap_em(a, b);
}

namespace std {

void swap(HashRecordProxy a, HashRecordProxy b) {
//  std::cerr << "std::swap(,)\n";
  swap_em(a, b);
}

void swap(HashRecordProxy& a, HashRecordProxy& b) {
//  std::cerr << "std::swap(&,&)\n";
  swap_em(a, b);
}

}

std::ostream& operator<<(std::ostream& out, const HashRecordProxy& r) {
  return out << to_hex(r.rec);
}
