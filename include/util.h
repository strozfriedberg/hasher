#pragma once

#include <algorithm>
#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>


template <class T, class D>
std::unique_ptr<T, D> make_unique_del(T* p, D&& deleter) {
  return std::unique_ptr<T, D>{p, std::forward<D>(deleter)};
}

template <typename F> struct function_traits;

template <typename R, typename A>
struct function_traits<R (&)(A)> {
  using result_type = R;
  using arg_type = A;
};

template <class F>
using ArgOf = typename std::remove_pointer<typename function_traits<F>::arg_type>::type;

template <class D>
std::unique_ptr<ArgOf<D>, D> make_unique_del(std::nullptr_t, D&& deleter) {
  return make_unique_del<ArgOf<D>, D>(nullptr, std::forward<D>(deleter));
}

template <typename C>
std::string to_hex(C beg, C end) {
  std::ostringstream o;
  o << std::setfill('0') << std::hex;
  for (C c = beg; c != end; ++c) {
    o << std::setw(2) << static_cast<uint32_t>(*c);
  }
  return o.str();
}

template <typename C>
std::string to_hex(const C& c) {
  return to_hex(&c[0], &c[c.size()]);
}

template <size_t N>
using hash_t = std::array<uint8_t, N>;

using md5_t = hash_t<16>;
using sha1_t = hash_t<20>;
using sha256_t = hash_t<32>;

uint8_t char_to_nibble(char c);

template <
  size_t N,
  class = typename std::enable_if<N % 2 == 0>::type
>
std::array<uint8_t, N> to_bytes(const char* c) {
  std::array<uint8_t, N> buf;
  uint8_t* out = &buf[0];
  const char* const end = c + 2*N;
  for ( ; c != end; ++out, c += 2) {
    *out = (char_to_nibble(*c) << 4) | char_to_nibble(*(c+1));
  }

  return buf;
}
