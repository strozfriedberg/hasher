#include "hset_decoder.h"

#include "hex.h"
#include "util.h"

#include <algorithm>
#include <map>
#include <ostream>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <iostream>

template <class T>
T read_pstring(const char* beg, const char*& i, const char* end) {
  const size_t len = read_le<uint16_t>(beg, i, end);
  THROW_IF(i + len > end, "out of data reading string at " << (i - beg));
  const char* sbeg = i;
  i += len;
  return T(sbeg, len);
}

struct FileHeader {
  uint64_t version;
  std::string_view hashset_name;
  std::string_view hashset_time;
  std::string_view hashset_desc;
};

std::ostream& operator<<(std::ostream& out, const FileHeader& fhdr) {
  return out << "FHDR\n"
             << ' ' << fhdr.version << '\n'
             << ' ' << fhdr.hashset_name << '\n'
             << ' ' << fhdr.hashset_time << '\n'
             << ' ' << fhdr.hashset_desc;
}

struct HashsetHeader {
  uint64_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;
  uint64_t hash_count;
};

std::ostream& operator<<(std::ostream& out, const HashsetHeader& hhdr) {
  return out << "HHDR\n"
             << ' ' << hhdr.hash_type << '\n'
             << ' ' << hhdr.hash_name << '\n'
             << ' ' << hhdr.hash_length << '\n'
             << ' ' << hhdr.hash_count;
}

struct HashsetData {
  const void* beg;
  const void* end;
};

std::ostream& operator<<(std::ostream& out, const HashsetData& hdat) {
  return out << "HDAT\n"
             << ' ' << hdat.beg << '\n'
             << ' ' << hdat.end;
}

struct SizesetData {
  const void* beg;
  const void* end;
};

std::ostream& operator<<(std::ostream& out, const SizesetData& sdat) {
  return out << "SDAT\n"
             << ' ' << sdat.beg << '\n'
             << ' ' << sdat.end;
}

struct RecordHashFieldDescriptor {
  uint64_t hash_type;
  std::string_view hash_name;
  uint64_t hash_length;
};

std::ostream& operator<<(std::ostream& out, const RecordHashFieldDescriptor& hrfd) {
  return out << "RHFD\n"
             << ' ' << hrfd.hash_type << '\n'
             << ' ' << hrfd.hash_name << '\n'
             << ' ' << hrfd.hash_length;
}

struct RecordSizeFieldDescriptor {
};

std::ostream& operator<<(std::ostream& out, const RecordSizeFieldDescriptor&) {
  return out << "RSFD";
}

struct RecordHeader {
  uint64_t record_length;
  uint64_t record_count;
  std::vector<std::variant<RecordHashFieldDescriptor, RecordSizeFieldDescriptor>> fields;
};

std::ostream& operator<<(std::ostream& out, const RecordHeader& rhdr) {
  out << "RHDR\n"
      << ' ' << rhdr.record_length << '\n'
      << ' ' << rhdr.record_count << '\n';

  for (const auto& f: rhdr.fields) {
    if (std::holds_alternative<RecordHashFieldDescriptor>(f)) {
      out << std::get<RecordHashFieldDescriptor>(f) << '\n';
    }
    else {
      out << std::get<RecordSizeFieldDescriptor>(f) << '\n';
    }
  }

  return out;
}

struct RecordData {
  const void* beg;
  const void* end;
};

std::ostream& operator<<(std::ostream& out, const RecordData& rdat) {
  return out << "RDAT\n"
             << ' ' << rdat.beg << '\n'
             << ' ' << rdat.end;
}

struct Chunk {
  enum Type {
    FHDR = 0x52444846,
    FEND = 0x444E4546,
    HDAT = 0x54414448,
    HHDR = 0x52444848,
    RHDR = 0x52444852,
    RHFD = 0x44464852,
    RSFD = 0x44465352,
    RDAT = 0x54414452,
    SDAT = 0x54414453
  };

  Type type;
  const char* dbeg;
  const char* dend;
};

Chunk decode_chunk(const char* beg, const char*& cur, const char* end) {
  const char* dbeg = cur + sizeof(uint64_t) + sizeof(uint32_t);
  const uint64_t len = read_le<uint64_t>(beg, cur, end);
  const uint32_t type = read_le<uint32_t>(beg, cur, end);

  cur = dbeg + len + 32;  // 32 is the length of the trailing hash

  return Chunk{ static_cast<Chunk::Type>(type), dbeg, dbeg + len };
}

struct Holder {
  FileHeader fhdr;
  std::vector<std::pair<HashsetHeader, HashsetData>> hsets;
  std::vector<std::pair<RecordHeader, RecordData>> recs;
  SizesetData sdat;
};

struct State {
  enum Type {
    INIT,
    DESC, // reading descriptors
    FEND,
    FHDR,
    HHDR,
    RHDR,
    SEND  // at section end
  };

  std::map<Chunk::Type, State::Type (*)(const Chunk&, Holder&)> allowed;
};

State::Type init_got_fhdr(const Chunk& ch, Holder& h) {
  // INIT -> FHDR

  const char* cur = ch.dbeg;
  h.fhdr.version = read_le<uint64_t>(ch.dbeg, cur, ch.dend);
  h.fhdr.hashset_name = read_pstring<std::string_view>(ch.dbeg, cur, ch.dend);
  h.fhdr.hashset_time = read_pstring<std::string_view>(ch.dbeg, cur, ch.dend);
  h.fhdr.hashset_desc = read_pstring<std::string_view>(ch.dbeg, cur, ch.dend);

  std::cerr << h.fhdr << "\n\n";

  return State::SEND;
}

State::Type hhdr_got_hdat(const Chunk& ch, Holder& h) {
  // HHDR -> HDAT

  h.hsets.back().second.beg = ch.dbeg;
  h.hsets.back().second.end = ch.dend;

  std::cerr << h.hsets.back().second << "\n\n";

  return State::SEND;
}

State::Type send_got_fend(const Chunk&, Holder&) {
  // HDAT, RDAT, SDAT -> FEND
  std::cerr << "FEND\n\n";
  return State::FEND;
}

State::Type send_got_hhdr(const Chunk& ch, Holder& h) {
  // HDAT, RDAT, SDAT -> HHDR
  const char* cur = ch.dbeg;

  h.hsets.emplace_back(
    HashsetHeader{
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend)
    },
    HashsetData()
  );

  std::cerr << h.hsets.back().first << "\n\n";

  return State::HHDR;
}

State::Type send_got_rhdr(const Chunk& ch, Holder& h) {
  // HDAT, RDAT, SDAT -> RHDR
  const char* cur = ch.dbeg;

  h.recs.emplace_back(
    RecordHeader{
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      {}
    },
    RecordData()
  );

  std::cerr << h.recs.back().first << "\n\n";

  return State::DESC;
}

State::Type send_got_sdat(const Chunk& ch, Holder& h) {
  // HDAT, RDAT, SDAT -> SDAT

  THROW_IF(h.sdat.beg, "there may be at most one SDAT chunk");

  h.sdat.beg = ch.dbeg;
  h.sdat.end = ch.dend;

  std::cerr << h.sdat << "\n\n";

  return State::SEND;
}

State::Type desc_got_rhfd(const Chunk& ch, Holder& h) {
  // RHDR, RHFD, RSFD -> RHFD
  const char* cur = ch.dbeg;

  auto& fields = h.recs.back().first.fields;

  fields.emplace_back(
    RecordHashFieldDescriptor{
      read_le<uint64_t>(ch.dbeg, cur, ch.dend),
      read_pstring<std::string_view>(ch.dbeg, cur, ch.dend),
      read_le<uint64_t>(ch.dbeg, cur, ch.dend)
    }
  );

  std::cerr << std::get<RecordHashFieldDescriptor>(fields.back()) << "\n\n";

  return State::DESC;
}

State::Type desc_got_rsfd(const Chunk&, Holder& h) {
  // RHDR, RHFD, RSFD -> RSFD

  auto& fields = h.recs.back().first.fields;

  THROW_IF(
    std::any_of(
      fields.begin(),
      fields.end(),
      [](const auto& v) {
        return std::holds_alternative<RecordSizeFieldDescriptor>(v);
      }
    ),
    "there may be at most one RSFD chunk per record section"
  );

  fields.emplace_back(
    RecordSizeFieldDescriptor()
  );

  std::cerr << std::get<RecordSizeFieldDescriptor>(fields.back()) << "\n\n";

  return State::DESC;
}

State::Type desc_got_rdat(const Chunk& ch, Holder& h) {
  // RHDR, RHFD, RSFD -> RDAT

  h.recs.back().second.beg = ch.dbeg;
  h.recs.back().second.end = ch.dend;

  return State::SEND;
}

const std::map<State::Type, State> SMAP{
  {
    State::INIT,
    State{ { 
      { Chunk::FHDR, init_got_fhdr }
    } } 
  },
  { 
    State::FEND,
    State{}
  },
  { 
    State::HHDR,
    State{ {
      { Chunk::HDAT, hhdr_got_hdat } 
    } }
  },
  {
    State::DESC,
    State{ {
      { Chunk::RDAT, desc_got_rdat },
      { Chunk::RHFD, desc_got_rhfd },
      { Chunk::RSFD, desc_got_rsfd }
    } }
  },
  {
    State::SEND,
    State { {
      { Chunk::HHDR, send_got_hhdr },
      { Chunk::RHDR, send_got_rhdr },
      { Chunk::SDAT, send_got_sdat },
      { Chunk::FEND, send_got_fend }
    } }
  }
};

// TODO: add validation flag

void read_chunks(const char* beg, const char* end) {

  const char* pos = beg + 8;  // TODO: don't skip magic 
  State::Type state = State::INIT;

  Holder h;

  while (state != State::FEND) {
    const State& st = SMAP.at(state);
    const Chunk ch = decode_chunk(beg, cur, end);

    const auto i = st.allowed.find(ch.type);
    THROW_IF(
      i == st.allowed.end(),
      "unexpected chunk type " << to_hex(&ch.type, &ch.type + sizeof(ch.type))
    );
    state = (i->second)(ch, h);
  }

  THROW_IF(cur != end, "found more data after FEND chunk");
}
