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

Matcher load_hashset(const char* beg, const char* end) {

  std::vector<std::pair<size_t, sha1_t>> table;

  auto fsm = make_unique_del(lg_create_fsm(0), lg_destroy_fsm);
  auto pmap = make_unique_del(lg_create_pattern_map(0), lg_destroy_pattern_map);
  auto pat = make_unique_del(lg_create_pattern(), lg_destroy_pattern);

  LG_Error* err = nullptr;
  LG_KeyOptions kopts{1, 0};

  const HashsetIterator iend;
  for (HashsetIterator i(beg, end); i != iend; ++i) {
/*
    std::cerr << std::get<0>(*i) << ", "
              << std::get<1>(*i) << ", "
              << to_hex(std::get<2>(*i)) << '\n';
*/
    table.emplace_back(std::get<1>(*i), std::get<2>(*i));

    lg_parse_pattern(pat.get(), std::get<0>(*i).c_str(), &kopts, &err);
    if (err) {
      // TODO: handle error
    }

    lg_add_pattern(fsm.get(), pmap.get(), pat.get(), "UTF-8", &err);
    if (err) {
      // TODO: handle error
    }
  }

  std::sort(table.begin(), table.end());

  LG_ProgramOptions popts{0};
  auto prog = make_unique_del(lg_create_program(fsm.get(), &popts), lg_destroy_program); 
  // TODO: check !prog

  return Matcher{std::move(table), std::move(prog)};
}

Matcher* sfhash_create_matcher(const char* beg, const char* end, LG_Error** err) {
  return new Matcher{load_hashset(beg, end)};
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
  LG_ContextOptions copt;
  auto ctx = make_unique_del(lg_create_context(matcher->prog.get(), &copt), lg_destroy_context);
  // TODO: check !ctx 

  bool hit = false;

  lg_search(ctx.get(), filename, filename + std::strlen(filename), 0, &hit, cb);
  lg_closeout_search(ctx.get(), &hit, cb);

  return hit; 
}

int sfhash_matcher_size(const Matcher* matcher) {
  return sizeof(decltype(Matcher::table)::value_type)*matcher->table.size() + lg_program_size(matcher->prog.get());
}

void sfhash_write_binary_matcher(const Matcher* matcher, void* buf) {
/*
  for (const auto& p: matcher->table) {
    *static_cast<size_t*>(buf) = p.first;
    buf += sizeof(size_t);
    *static_cast<sha1_t*>(buf) = p.second;
    buf += sizeof(sha1_t);
  }

  lg_write_program(matcher->prog.get(), buf);
*/
}

Matcher* sfhash_read_binary_matcher(const void* beg, const void* end) {
  return nullptr; 
}

void sfhash_destroy_matcher(Matcher* matcher) {
  delete matcher;
}
