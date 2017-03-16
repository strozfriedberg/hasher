#include "hasher.h"
#include "matcher.h"
#include "util.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <utility>
#include <vector>

#include <boost/lexical_cast.hpp>

using Matcher = SFHASH_FileMatcher;

std::tuple<std::string, size_t, sha1_t> parse_line(const char* beg, const char* const end) {
  const char* i = beg;
  const char* j;

  THROW_IF(i == end, "premature end of tokens");
  j = std::find(i, end, '\t');
  THROW_IF(j == end, "premature end of tokens");
  std::string name(i, j);

  i = j + 1;
  THROW_IF(i == end, "premature end of tokens");
  j = std::find(i, end, '\t');
  THROW_IF(j == end, "premature end of tokens");
  const size_t size = boost::lexical_cast<size_t>(i, j - i);

  i = j + 1;
  THROW_IF(i == end, "premature end of tokens");
  j = i + 40;
  THROW_IF(j != end, "too many tokens");
  sha1_t hash = to_bytes<20>(i);

  return {std::move(name), size, std::move(hash)}; 
}

std::unique_ptr<Matcher> load_hashset(const char* beg, const char* end, LG_Error** err) {
  auto fsm = make_unique_del(lg_create_fsm(0), lg_destroy_fsm);
  if (!fsm) {
    return nullptr;
  }

  auto pmap = make_unique_del(lg_create_pattern_map(0), lg_destroy_pattern_map);
  if (!pmap) {
    return nullptr; 
  }

  auto pat = make_unique_del(lg_create_pattern(), lg_destroy_pattern);
  if (!pat) {
    return nullptr;
  }

  // The last byte is either \n or part of the last line if some horrible
  // person has a file which doesn't end with EOL, count it as 1 either way.
  const size_t lines = std::count(beg, end-1, '\n') + 1;

  std::vector<std::pair<size_t, sha1_t>> table;
  table.reserve(lines);

  const LG_KeyOptions kopts{1, 0};

  const LineIterator lend(end, end);
  for (LineIterator l(beg, end); l != lend; ++l) {
    auto t = parse_line(l->first, l->second);

/*
    std::cerr << std::get<0>(t) << ", "
              << std::get<1>(t) << ", "
              << to_hex(std::get<2>(t)) << '\n';
*/
    table.emplace_back(std::get<1>(t), std::get<2>(t));

    lg_parse_pattern(pat.get(), std::get<0>(t).c_str(), &kopts, err);
    if (*err) {
      return nullptr;
    }

    lg_add_pattern(fsm.get(), pmap.get(), pat.get(), "UTF-8", err);
    if (*err) {
      return nullptr;
    }
  }

  const LG_ProgramOptions popts{0};
  auto prog = make_unique_del(
    lg_create_program(fsm.get(), &popts), lg_destroy_program
  );
  if (!prog) {
    return nullptr;
  }

  std::sort(table.begin(), table.end());

  return std::unique_ptr<Matcher>(
    new Matcher{std::move(table), std::move(prog)}
  );
}

Matcher* sfhash_create_matcher(const char* beg, const char* end, LG_Error** err) {
    return load_hashset(beg, end, err).release();
}

int sfhash_matcher_has_size(const Matcher* matcher, uint64_t size) {
  const auto i = std::lower_bound(
    matcher->table.begin(), matcher->table.end(),
    std::make_pair(size, sha1_t())
  );
  return i == matcher->table.end() ? false : i->first == size;
}

int sfhash_matcher_has_hash(const Matcher* matcher, uint64_t size, const uint8_t* sha1) {
  sha1_t hash;
  std::memcpy(&hash[0], sha1, sizeof(sha1_t));

  return std::binary_search(
    matcher->table.begin(), matcher->table.end(),
    std::make_pair(size, std::move(hash))
  );
}

void cb(void *userData, const LG_SearchHit* const) {
  *static_cast<bool*>(userData) = true;
} 

int sfhash_matcher_has_filename(const Matcher* matcher, const char* filename) {
  const LG_ContextOptions copt{};
  auto ctx = make_unique_del(
    lg_create_context(matcher->prog.get(), &copt), lg_destroy_context
  );

  bool hit = false;

  lg_search(ctx.get(), filename, filename + std::strlen(filename), 0, &hit, cb);
  lg_closeout_search(ctx.get(), &hit, cb);

  return hit; 
}

size_t table_size(const Matcher* matcher) {
  return sizeof(decltype(Matcher::table)::value_type) * matcher->table.size();
}

int sfhash_matcher_size(const Matcher* matcher) {
  return sizeof(size_t) +
         table_size(matcher) +
         lg_program_size(matcher->prog.get());
}

void sfhash_write_binary_matcher(const Matcher* matcher, void* buf) {
  const size_t tlen = table_size(matcher); 
  *static_cast<size_t*>(buf) = tlen;
  buf = static_cast<void*>(static_cast<size_t*>(buf) + 1);
  std::memcpy(buf, matcher->table.data(), tlen);
  buf = static_cast<void*>(static_cast<uint8_t*>(buf) + tlen);
  lg_write_program(matcher->prog.get(), buf);
}

Matcher* sfhash_read_binary_matcher(const void* beg, const void* end) {
  const uint8_t* buf = static_cast<const uint8_t*>(beg);
  const size_t tlen = *reinterpret_cast<const size_t*>(buf);
  buf += sizeof(size_t);
 
  if (buf + tlen > end) {
    return nullptr; 
  }

  std::vector<std::pair<size_t, sha1_t>> table(
    tlen / sizeof(std::pair<size_t, sha1_t>)
  );
  std::memcpy(table.data(), buf, tlen);
  buf += tlen;
 
  const size_t plen = static_cast<const uint8_t*>(end) - buf;
  auto prog = make_unique_del(
    // TODO: remove the const_cast after fixing the liblg API
    lg_read_program(const_cast<uint8_t*>(buf), plen),
    lg_destroy_program
  );
  if (!prog) {
    return nullptr;
  }

  return new Matcher{std::move(table), std::move(prog)};
}

void sfhash_destroy_matcher(Matcher* matcher) {
  delete matcher;
}
