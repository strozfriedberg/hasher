#include <ostream>
#include <string_view>
#include <vector>

#include <boost/endian/conversion.hpp>

template <class T>
T to_be(T i) {
  return boost::endian::native_to_big(i);
}

template <class T>
T to_le(T i) {
  return boost::endian::native_to_little(i);
}

template <class Out>
size_t write_to(Out& out, const void* buf, size_t len);

template <>
size_t write_to(std::ostream& out, const void* buf, size_t len) {
  out.write(static_cast<const char*>(buf), len);
  return len;
}

template <>
size_t write_to(std::vector<char>& out, const void* buf, size_t len) {
  out.insert(
    out.end(),
    static_cast<const char*>(buf),
    static_cast<const char*>(buf) + len
  );
  return len;
}

template <class T, T (*EndianFunc)(T), class Out>
size_t write_i(T i, Out& out) {
  const T l = EndianFunc(i);
  return write_to(out, reinterpret_cast<const char*>(&l), sizeof(i));
}

template <class T, class Out>
size_t write_le(T i, Out& out) {
  return write_i<T, to_le>(i, out);
}

template <class T, class Out>
size_t write_be(T i, Out& out) {
  return write_i<T, to_be>(i, out);
}

template <class Out>
size_t write_pstring(const std::string_view s, Out& out) {
  return write_le<uint16_t>(s.length(), out) +
         write_to(out, s.data(), s.length());
}
