#include "helper.h"

#include <fstream>
#include <iterator>

std::vector<char> read_file(const std::string& path) {
  std::ifstream in(path, std::ios_base::binary);
  in.exceptions(std::ifstream::badbit | std::ifstream::failbit);
  return std::vector<char>(std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>());
}
