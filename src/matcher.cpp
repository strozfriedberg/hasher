#include "hasher/api.h"
#include "error.h"
#include "hashset.h"
#include "matcher.h"
#include "parser.h"
#include "sizeset.h"
#include "throw.h"
#include "util.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <iterator>
#include <utility>

using Error = SFHASH_Error;
using Matcher = SFHASH_FileMatcher;
using SizeSet = SFHASH_SizeSet;

std::unique_ptr<Matcher> load_hashset(const char* beg, const char* end, LG_Error** err) {
  auto fsm = make_unique_del(lg_create_fsm(0), lg_destroy_fsm);
  if (!fsm) {
    return nullptr;
  }

  auto prog = make_unique_del(lg_create_program(0), lg_destroy_program);
  if (!prog) {
    return nullptr;
  }

  auto pat = make_unique_del(lg_create_pattern(), lg_destroy_pattern);
  if (!pat) {
    return nullptr;
  }

  // The last byte is either \n or part of the last line if some horrible
  // person has a file which doesn't end with EOL, count it as 1 either way.
  const size_t lines = std::count(beg, end - 1, '\n') + 1;

  auto sizes = make_unique_del(new SizeSet, sfhash_destroy_sizeset);
  sizes->sizes.reserve(lines);

  std::unique_ptr<std::array<uint8_t, 20>[]> hashes(
    new std::array<uint8_t, 20>[lines]
  );
  std::array<uint8_t, 20>* hcur = hashes.get();

  const LG_KeyOptions kopts{1, 0, 0};

  auto err_chain = make_unique_del(static_cast<LG_Error*>(nullptr), lg_free_error);
  LG_Error* tail_err  = nullptr;
  LG_Error* local_err = nullptr;

  int lineno = 1;
  const LineIterator lend(end, end);
  for (LineIterator l(beg, end); l != lend; ++l, ++lineno) {
    // skip empty lines
    if (l->first == l->second) {
      continue;
    }

    try {
      auto t = parse_line(l->first, l->second);

      // turn the filename into a pattern
      if (t.flags & HAS_FILENAME) {
        lg_parse_pattern(pat.get(), t.name.c_str(), &kopts, &local_err);
        THROW_IF(local_err, "");

        lg_add_pattern(fsm.get(), prog.get(), pat.get(), "UTF-8", 0, &local_err);
        THROW_IF(local_err, "");
      }

      // put the size and hash into the table
      if (t.flags & HAS_SIZE) {
        sizes->sizes.insert(t.size);
      }

      if (t.flags & HAS_HASH) {
        *hcur = t.hash;
        ++hcur;
      }
    }
    catch (const std::runtime_error& e) {
      if (!local_err) {
        local_err = new LG_Error{new char[std::strlen(e.what()) + 1],
                                 nullptr,
                                 nullptr,
                                 nullptr,
                                 lineno,
                                 nullptr};
        std::strcpy(local_err->Message, e.what());
      }

      if (!err_chain) {
        tail_err = local_err;
        err_chain.reset(tail_err);
      }
      else {
        tail_err->Next = local_err;
        tail_err       = local_err;
      }
      local_err = nullptr;
    }
  }

  if (err_chain) {
    *err = err_chain.release();
  }

  const LG_ProgramOptions popts{0};
  if (!lg_compile_program(fsm.get(), prog.get(), &popts)) {
    return nullptr;
  }

  std::sort(hashes.get(), hcur);

  auto hptr = make_unique_del(
    make_hashset<20>(hashes.get(), hcur, std::numeric_limits<uint32_t>::max(), false),
    sfhash_destroy_hashset
  );

  return std::unique_ptr<Matcher>(
    new Matcher{std::move(sizes), std::move(hptr), std::move(prog)}
  );
}

Matcher* sfhash_create_matcher(const void* beg, const void* end, Error** err) {
  LG_Error* lg_err = nullptr;
  auto m = load_hashset(static_cast<const char*>(beg),
                        static_cast<const char*>(end), &lg_err);
  if (lg_err) {
    fill_error(err, lg_err);
  }
  return m.release();
}

bool sfhash_matcher_has_size(const Matcher* matcher, uint64_t size) {
  return sfhash_lookup_sizeset(matcher->Sizes.get(), size);
}

bool sfhash_matcher_has_hash(const Matcher* matcher, const uint8_t* sha1) {
  return sfhash_lookup_hashset(matcher->Hashes.get(), sha1);
}

void cb(void* userData, const LG_SearchHit* const) {
  *static_cast<bool*>(userData) = true;
}

bool sfhash_matcher_has_filename(const Matcher* matcher, const char* filename) {
  bool hit  = false;
  auto prog = matcher->Prog.get();
  if (prog) {
    const LG_ContextOptions copt{};
    auto ctx = make_unique_del(lg_create_context(prog, &copt), lg_destroy_context);

    lg_search(ctx.get(), filename, filename + std::strlen(filename), 0, &hit, cb);
    lg_closeout_search(ctx.get(), &hit, cb);
  }

  return hit;
}

/*
std::unique_ptr<SFHASH_FileMatcher> load_hashset_binary(const char* beg, const char* end) {
  const char* cur = beg;

  const size_t radius = (cur[0] << 24) | (cur[1] << 16) | (cur[2] << 8) | cur[3];
  cur += 4;
  const size_t record_size = (cur[0] << 24) | (cur[1] << 16) | (cur[2] << 8) | cur[3];
  cur += 4;

  // std::cerr << "radius == " << radius << '\n'
  //           << "records == " << (end - cur)/record_size << std::endl;

  std::vector<sha1_t> hashes;
  hashes.reserve((end - cur)/record_size);

  while (cur < end) {
    hashes.push_back(*reinterpret_cast<const sha1_t*>(cur));
    cur += sizeof(sha1_t);
  }

  auto prog = make_unique_del(nullptr, lg_destroy_program);

  return std::unique_ptr<Matcher>(
    new Matcher{{}, std::move(hashes), std::move(prog), radius}
  );
}

Matcher* sfhash_create_matcher_binary(const char* beg, const char* end) {
  return load_hashset_binary(beg, end).release();
}
*/

/*
size_t sizes_size(const Matcher* matcher) {
  return sizeof(decltype(Matcher::Sizes)::value_type) * matcher->Sizes.size();
}

size_t hashes_size(const Matcher* matcher) {
  return sizeof(decltype(Matcher::Hashes)::value_type) * matcher->Hashes.size();
}

int sfhash_matcher_size(const Matcher* matcher) {
  return sizeof(size_t) + sizes_size(matcher) + + lg_program_size(matcher->Prog.get());
}

void sfhash_write_binary_matcher(const Matcher* matcher, void* buf) {
  const size_t tlen          = table_size(matcher);
  *static_cast<size_t*>(buf) = tlen;

  buf = static_cast<void*>(static_cast<size_t*>(buf) + 1);
  std::memcpy(buf, matcher->Table.data(), tlen);
  buf = static_cast<void*>(static_cast<uint8_t*>(buf) + tlen);
  lg_write_program(matcher->Prog.get(), buf);
}

Matcher* sfhash_read_binary_matcher(const void* beg, const void* end) {
  const uint8_t* buf = static_cast<const uint8_t*>(beg);
  const size_t tlen  = *reinterpret_cast<const size_t*>(buf);
  buf += sizeof(size_t);

  if (buf + tlen > end) {
    return nullptr;
  }

  std::vector<std::pair<uint64_t, sha1_t>> table(tlen / sizeof(std::pair<uint64_t, sha1_t>));
  std::memcpy(table.data(), buf, tlen);
  buf += tlen;

  const size_t plen = static_cast<const uint8_t*>(end) - buf;

  auto prog = make_unique_del(
    // TODO: remove the const_cast after fixing the liblg API
    lg_read_program(const_cast<uint8_t*>(buf), plen),
    lg_destroy_program);

  if (!prog) {
    return nullptr;
  }

  return new Matcher{std::move(table), std::move(prog)};
}
*/

void sfhash_destroy_matcher(Matcher* matcher) {
  delete matcher;
}
