#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>

size_t run(
  const std::string hashset_name,
  const std::string hashset_desc,
  char const* const* hash_type_names,
  size_t hash_type_names_count,
  std::istream& in,
  std::ostream& out
);
