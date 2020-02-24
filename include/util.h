#pragma once

#include "throw.h"

#include <array>
#include <memory>
#include <type_traits>

// TODO: eliminate these
template <size_t N>
using hash_t = std::array<uint8_t, N>;

using md5_t    = hash_t<16>;
using sha1_t   = hash_t<20>;
using sha256_t = hash_t<32>;

//
// make_unique_del and helpers
//

template <class T, class D>
std::unique_ptr<T, D> make_unique_del(T* p, D&& deleter) {
  return std::unique_ptr<T, D>{p, std::forward<D>(deleter)};
}

template <typename F>
struct function_traits;

template <typename R, typename A>
struct function_traits<R (&)(A)> {
  using result_type = R;
  using arg_type    = A;
};

template <class F>
using ArgOf = typename std::remove_pointer<typename function_traits<F>::arg_type>::type;

template <class D>
std::unique_ptr<ArgOf<D>, D> make_unique_del(std::nullptr_t, D&& deleter) {
  return make_unique_del<ArgOf<D>, D>(nullptr, std::forward<D>(deleter));
}

//
// Templates for reading unsigned integers from raw bytes
//

template <typename out_t, bool le, size_t i>
out_t shifter(const uint8_t* x) {
  return static_cast<out_t>(x[i]) << (8 * (le ? i : sizeof(out_t)-1-i));
}

template <typename out_t, bool le, size_t i>
out_t orer(const uint8_t* x) {
  return i == 0 ?
    shifter<out_t, le, i>(x) :
    (orer<out_t, le, i == 0 ? 0 : i-1>(x) | shifter<out_t, le, i>(x));
}

template <typename out_t, bool le>
out_t to_uint(const uint8_t* x) {
  return orer<out_t, le, sizeof(out_t)-1>(x);
}

template <typename out_t>
out_t to_uint_le(const uint8_t* x) {
  return orer<out_t, true, sizeof(out_t)-1>(x);
}

template <typename out_t>
out_t to_uint_be(const uint8_t* x) {
  return orer<out_t, false, sizeof(out_t)-1>(x);
}

template <typename out_t, bool le>
out_t read_uint(const uint8_t* beg, const uint8_t*& i, const uint8_t* end) {
  THROW_IF(
    i + sizeof(out_t) > end,
    "out of data reading " << sizeof(out_t) << " bytes at " << (i-beg)
  );
  const out_t r = to_uint<out_t, le>(i);
  i += sizeof(out_t);
  return r;
}

template <typename out_t>
out_t read_le(const uint8_t* beg, const uint8_t*& i, const uint8_t* end) {
  return read_uint<out_t, true>(beg, i, end);
}

template <typename out_t>
out_t read_be(const uint8_t* beg, const uint8_t*& i, const uint8_t* end) {
  return read_uint<out_t, false>(beg, i, end);
}
