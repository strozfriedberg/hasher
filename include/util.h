#include <iomanip>
#include <memory>
#include <sstream>
#include <string>

template <class T, class D>
std::unique_ptr<T, D> make_unique_del(T* p, D&& deleter) {
  return std::unique_ptr<T, D>{p, std::forward<D>(deleter)};
}

template <typename C>
std::string to_hex(const C* beg, const C* end) {
  std::ostringstream o;
  o << std::setfill('0') << std::hex;
  for (const C* c = beg; c != end; ++c) {
    o << std::setw(2) << static_cast<uint32_t>(*c);
  }
  return o.str();
}
