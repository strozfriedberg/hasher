#include "hex.h"
#include "parser.h"
#include "throw.h"

#include <boost/lexical_cast.hpp>

using value_type = std::pair<const char*, const char*>;

const char* find_nonws(const char* beg, const char* end) {
  return std::find_if_not(beg, end, [](char c) { return c == ' '; });
}

ParsedLine parse_line(const char* beg, const char* const end) {

  bool have_name = false, have_size = false, have_hash = false;
  uint8_t flags = BLANK_LINE;
  std::string name;
  uint64_t size = 0;
  std::array<uint8_t, 20> hash{};

  if (beg != end) {
    const char* cbeg = beg;
    const char* cend;

    // go to column 1
    cend = std::find(cbeg, end, '\t');

    // parse the filename
    if (cbeg != cend) {
      // filename column is nonempty
      name.assign(cbeg, cend);
      have_name = true;
    }

    // go to column 2
    cbeg = std::min(cend + 1, end);
    cend = std::find(cbeg, end, '\t');

    // parse the file size
    if (cbeg != cend) {
      // file size column is nonempty

      // eat whitespace
      const char* i = find_nonws(cbeg, cend);
      if (i != cend) {

        // check for a minus sign, as lexical_cast rolls over negatives
        THROW_IF(*i == '-', "bad file size '" << std::string(i, cend) << "'");

        // eat trailing whitespace
        const char* j = std::find(i, cend, ' ');
        if (j != cend) {
          // reject trailing nonwhitespace
          THROW_IF(find_nonws(j + 1, cend) != cend,
                   "bad file size '" << std::string(i, cend) << "'");
        }

        try {
          size = boost::lexical_cast<uint64_t>(i, j - i);
        }
        catch (const boost::bad_lexical_cast& e) {
          THROW("bad file size '" << std::string(i, j) << "'");
        }

        have_size = true;
      }
    }

    // go to column 3
    cbeg = std::min(cend + 1, end);
    cend = std::find(cbeg, end, '\t');

    // parse the hash
    if (cbeg != cend) {
      // eat whitespace
      const char* i = find_nonws(cbeg, cend);
      const char* j = std::find(std::min(i + 1, cend), cend, ' ');

      THROW_IF(j - i != 40,
               "file hash is " << (j - i > 40 ? "longer" : "shorter")
                               << " than 40 characters");

      // reject trailing nonwhitespace
      THROW_IF(j + 1 < cend && find_nonws(j + 1, cend) != cend,
               "bad hash '" << std::string(i, cend) << "'");

      hash      = to_bytes<20>(i);
      have_hash = true;
    }
  }

  THROW_IF(have_hash && !have_size, "missing file size");
  THROW_IF(have_size && !have_hash, "missing hash");

  if (have_name) {
    flags |= HAS_FILENAME;
  }

  if (have_size) {
    flags |= HAS_SIZE;
  }

  if (have_hash) {
    flags |= HAS_HASH;
  }

  return {std::move(name), std::move(hash), size, flags};
}

const value_type& LineIterator::operator*() const {
  return Pos;
}

const value_type* LineIterator::operator->() const {
  return &Pos;
}

LineIterator& LineIterator::operator++() {
  if (Pos.second == End) {
    Pos.first = End;
  }
  else {
    Pos.first  = Pos.second + (*Pos.second == '\r' ? 2 : 1);
    Pos.second = find_next(Pos.first, End);
  }
  return *this;
}

LineIterator LineIterator::operator++(int) {
  LineIterator i(*this);
  ++*this;
  return i;
}

bool LineIterator::operator==(const LineIterator& o) const {
  return Pos == o.Pos;
}

bool LineIterator::operator!=(const LineIterator& o) const {
  return !(*this == o);
}

const char* LineIterator::find_next(const char* cur, const char* end) {
  const char* i = std::find(cur, end, '\n');
  return (i == end || *(i - 1) != '\r') ? i : i - 1;
}
