#include "parser.h"
#include "throw.h"

#include <boost/lexical_cast.hpp>

std::tuple<uint8_t, std::string, uint64_t, sha1_t> parse_line(const char* beg, const char * const end) {
  const char* i = beg;
  const char* j;

  if (i == end) {
    // we have a blank line
    return { BLANK_LINE, "", 0, sha1_t() };
  }

  // read the filename (possibly the sole column, possilbly an empty column)
  j = std::find(i, end, '\t');
  std::string name(i, j);

  if (j == end) {
    // we have only the filename
    return { HAS_FILENAME, std::move(name), 0, sha1_t() };
  }

  // read the file size
  i = j + 1;
  THROW_IF(i >= end, "missing file size and hash");

  // we must check for a minus sign, as lexical_cast rolls over negatives
  const char tab_or_minus[] = "\t-";
  j = std::find_first_of(i, end, tab_or_minus, tab_or_minus + 2);
  THROW_IF(j == end, "missing file hash");
  if (*j == '-') {
    j = std::find(j, end, '\t');
    THROW("bad file size '" << std::string(i, j) << "'");
  }

  uint64_t size;
  try {
    size = boost::lexical_cast<uint64_t>(i, j - i);
  }
  catch (const boost::bad_lexical_cast& e) {
    THROW("bad file size '" << std::string(i, j) << "'");
  }

  // read the SHA1
  i = j + 1;
  THROW_IF(i >= end, "missing file hash");
  j = i + 40;
  THROW_IF(
    j != end,
    "file hash is " << (j < end ? "longer" : "shorter")
                    << " than 40 characters"
  );
  sha1_t hash = to_bytes<20>(i);

  return {
    HAS_SIZE_AND_HASH | (name.empty() ? 0 : HAS_FILENAME),
    std::move(name), size, std::move(hash)
  };
}
