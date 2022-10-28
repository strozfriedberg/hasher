#pragma once

#include <string_view>

#include <boost/endian/conversion.hpp>

#include "throw.h"

//
// Endianness conversion
//

template <class T>
T to_be(T i) {
  return boost::endian::native_to_big(i);
}

template <class T>
T to_le(T i) {
  return boost::endian::native_to_little(i);
}

template <class T>
T from_le(T i) {
  return boost::endian::little_to_native(i);
}

template <class T>
T from_be(T i) {
  return boost::endian::big_to_native(i);
}

//
// Read
//

template <typename T, T (*EndianFunc)(T), typename C>
T read_i(const C* beg, const C*& i, const C* end) {
  THROW_IF(
    i + sizeof(T) > end,
    "out of data reading " << sizeof(T) << " bytes at " << (i - beg)
  );

  const T r = EndianFunc(*reinterpret_cast<const T*>(i));
  i += sizeof(T);
  return r;
}

template <typename T, typename C>
T read_le(const C* beg, const C*& i, const C* end) {
  return read_i<T, from_le>(beg, i, end);
}

template <typename T, typename C>
T read_be(const C* beg, const C*& i, const C* end) {
  return read_i<T, from_be>(beg, i, end);
}

template <class T>
T read_pstring(const char* beg, const char*& i, const char* end) {
  const size_t len = read_le<uint16_t>(beg, i, end);
  THROW_IF(i + len > end, "out of data reading string at " << (i - beg));
  const char* sbeg = i;
  i += len;
  return T(sbeg, len);
}

//
// Write
//

template <class Out>
size_t write_to(Out& out, const void* buf, size_t len);

template <class Out>
size_t write_to(Out* out, const void* buf, size_t len);

template <class T, T (*EndianFunc)(T), class Out>
size_t write_i(T i, Out&& out) {
  const T l = EndianFunc(i);
  return write_to(std::forward<Out>(out), &l, sizeof(i));
}

template <class T, class Out>
size_t write_le(T i, Out&& out) {
  return write_i<T, to_le>(i, std::forward<Out>(out));
}

template <class T, class Out>
size_t write_be(T i, Out&& out) {
  return write_i<T, to_be>(i, std::forward<Out>(out));
}

template <class Out>
size_t write_pstring(const std::string_view s, Out& out) {
  return write_le<uint16_t>(s.length(), out) +
         write_to(out, s.data(), s.length());
}

template <class Out>
size_t write_pstring(const std::string_view s, Out* out) {
  const auto beg = out;
  out += write_le<uint16_t>(s.length(), out);
  out += write_to(out, s.data(), s.length());
  return out - beg;
}

template <class Out>
size_t write_bytes(const void* buf, size_t len, Out&& out) {
  return write_to(std::forward<Out>(out), buf, len);
}

template <class Out>
size_t write_byte(size_t len, uint8_t b, Out& out) {
  for (size_t i = 0; i < len; ++i) {
    write_to(out, &b, 1);
  }
  return len;
}

template <class Out>
size_t write_byte(size_t len, uint8_t b, Out* out) {
  // TODO: specialize this to use std::memset
  for (size_t i = 0; i < len; ++i) {
    out += write_to(out, &b, 1);
  }
  return len;
}
