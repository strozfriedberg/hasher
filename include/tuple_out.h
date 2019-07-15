/*
  liblightgrep: not the worst forensics regexp engine
  Copyright (C) 2015, Lightbox Technologies, Inc

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <ostream>
#include <tuple>

namespace detail {
  template <class T, std::size_t N>
  struct tuple_printer {
    static void print(std::ostream& o, const T& t) {
      tuple_printer<T, N - 1>::print(o, t);
      o << ", " << std::get<N - 1>(t);
    }
  };

  template <class T>
  struct tuple_printer<T, 1> {
    static void print(std::ostream& o, const T& t) {
      o << std::get<0>(t);
    }
  };

  // empty tuple specialization
  template <class T>
  struct tuple_printer<T, 0> {
    static void print(std::ostream&, const T&) {}
  };
} // namespace detail

template <class... Args>
std::ostream& operator<<(std::ostream& o, const std::tuple<Args...>& t) {
  o << '(';
  detail::tuple_printer<decltype(t), sizeof...(Args)>::print(o, t);
  o << ')';
  return o;
}
