#pragma once

#include "throw.h"

#include <memory>
#include <type_traits>

#include <boost/endian/conversion.hpp>

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
// Functions for reading integers from bytes
//

template <typename T, typename C>
T read_le(const C* beg, const C*& i, const C* end) {
  THROW_IF(
    i + sizeof(T) > end,
    "out of data reading " << sizeof(T) << " bytes at " << (i - beg)
  );

  const T r = boost::endian::little_to_native(*reinterpret_cast<const T*>(i));
  i += sizeof(T);
  return r;
}

//
// Functions for writing unsigned integers to bytes
//

void write_le_8(uint64_t in, const uint8_t* beg, uint8_t*& out, const uint8_t* end);
