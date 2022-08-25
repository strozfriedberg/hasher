#include "hset_decoder.h"

#include "hex.h"
#include "util.h"

#include <algorithm>
#include <map>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <iostream>

std::string read_pstring(const char* beg, const char*& i, const char* end) {
  const uint32_t len = read_le<uint16_t>(beg, i, end);
  THROW_IF(i + len > end, "out of data reading string at " << (i - beg));
  const char* sbeg = i;
  return std::string(sbeg, i += len);
}

struct FileHeader {
  uint64_t version;
  std::string hashset_name;
  std::string hashset_time;
  std::string hashset_desc;
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
  std::string hash_name;
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

Chunk decode_chunk(const char* beg, const char*& pos, const char* end) {
  const char* dbeg = pos + sizeof(uint64_t) + sizeof(uint32_t);
  const uint64_t len = read_le<uint64_t>(beg, pos, end);
  const uint32_t type = read_le<uint32_t>(beg, pos, end);

  pos = dbeg + len + 32;  // 32 is the length of the trailing hash
 
  return Chunk{ static_cast<Chunk::Type>(type), dbeg, dbeg + len };   
}

struct Holder {
  FileHeader fhdr;
  std::vector<std::pair<HashsetHeader, HashsetData>> hsets; 
};

struct State {
  enum Type {
    INIT,
    FEND,
    FHDR,
    HDAT,
    HHDR,
    RHDR,
    RHFD,
    RSFD,
    RDAT,
    SDAT
  };
  
  std::map<Chunk::Type, State::Type (*)(const Chunk&, Holder&)> allowed;
};

State::Type init_got_fhdr(const Chunk& ch, Holder& h) {
  // INIT -> FHDR

  const char* pos = ch.dbeg;
  h.fhdr.version = read_le<uint64_t>(ch.dbeg, pos, ch.dend);
  h.fhdr.hashset_name = read_pstring(ch.dbeg, pos, ch.dend); 
  h.fhdr.hashset_time = read_pstring(ch.dbeg, pos, ch.dend); 
  h.fhdr.hashset_desc = read_pstring(ch.dbeg, pos, ch.dend); 

  std::cerr << h.fhdr << "\n\n";

  return State::FHDR;
}

void handle_hhdr(const Chunk& ch, Holder& h) {
  const char* pos = ch.dbeg;

  h.hsets.emplace_back(
    HashsetHeader{   
      read_le<uint64_t>(ch.dbeg, pos, ch.dend),
      read_pstring(ch.dbeg, pos, ch.dend),
      read_le<uint64_t>(ch.dbeg, pos, ch.dend),
      read_le<uint64_t>(ch.dbeg, pos, ch.dend)
    },
    HashsetData()
  );

  std::cerr << h.hsets.back().first << "\n\n";
}

State::Type fhdr_got_hhdr(const Chunk& ch, Holder& h) {
  // FHDR -> HHDR
  handle_hhdr(ch, h);
  return State::HHDR;
}

State::Type fhdr_got_rhdr(const Chunk&, Holder&) {
  // FHDR -> RHDR
  return State::RHDR;
}

State::Type fhdr_got_sdat(const Chunk&, Holder&) {
  // FHDR -> SDAT
  return State::SDAT;
}

State::Type hhdr_got_hdat(const Chunk& ch, Holder& h) {
  // HHDR -> HDAT

  h.hsets.back().second.beg = ch.dbeg;
  h.hsets.back().second.end = ch.dend;

  std::cerr << h.hsets.back().second << "\n\n";

  return State::HDAT;
}

State::Type hdat_got_fend(const Chunk&, Holder&) {
  // HDAT -> FEND
  std::cerr << "FEND\n\n";
  return State::FEND;
}

State::Type hdat_got_hhdr(const Chunk& ch, Holder& h) {
  // HDAT -> HHDR
  handle_hhdr(ch, h);
  return State::HHDR;
}

State::Type hdat_got_rhdr(const Chunk&, Holder&) {
  // HDAT -> RHDR
  return State::RHDR;
}

State::Type hdat_got_sdat(const Chunk&, Holder&) {
  // HDAT -> SDAT
  return State::SDAT;
}

State::Type rhdr_got_rhfd(const Chunk&, Holder&) {
  // RHDR -> RHFD
  return State::RHFD;
}

State::Type rhdr_got_rsfd(const Chunk&, Holder&) {
  // RHDR -> RSFD
  return State::RSFD;
}

State::Type rhfd_got_rhfd(const Chunk&, Holder&) {
  // RHFD -> RHFD
  return State::RHFD;
}

State::Type rhfd_got_rsfd(const Chunk&, Holder&) {
  // RHFD -> RSFD
  return State::RSFD;
}

State::Type rhfd_got_rdat(const Chunk&, Holder&) {
  // RHFD -> RDAT
  return State::RDAT;
}

State::Type rsfd_got_rhfd(const Chunk&, Holder&) {
  // RHFD -> RHFD
  return State::RHFD;
}

State::Type rsfd_got_rdat(const Chunk&, Holder&) {
  // RHFD -> RDAT
  return State::RDAT;
}

State::Type rdat_got_fend(const Chunk&, Holder&) {
  // RDAT -> FEND
  std::cerr << "FEND\n\n";
  return State::FEND;
}

State::Type rdat_got_hhdr(const Chunk& ch, Holder& h) {
  // RDAT -> HHDR
  handle_hhdr(ch, h);
  return State::HHDR;
}

State::Type rdat_got_rhdr(const Chunk&, Holder&) {
  // RDAT -> RHDR
  return State::RHDR;
}

State::Type rdat_got_sdat(const Chunk&, Holder&) {
  // RDAT -> SDAT
  return State::SDAT;
}

State::Type sdat_got_fend(const Chunk&, Holder&) {
  // SDAT -> FEND
  std::cerr << "FEND\n\n";
  return State::FEND;
}

State::Type sdat_got_hhdr(const Chunk& ch, Holder& h) {
  // SDAT -> HHDR
  handle_hhdr(ch, h);
  return State::HHDR;
}

State::Type sdat_got_rhdr(const Chunk&, Holder&) {
  // SDAT -> RHDR
  return State::RHDR;
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
    State::FHDR,
    State{ {
      { Chunk::HHDR, fhdr_got_hhdr },
      { Chunk::RHDR, fhdr_got_rhdr },
      { Chunk::SDAT, fhdr_got_sdat }
    } }
  },
  { 
    State::HHDR,
    State{ {
      { Chunk::HDAT, hhdr_got_hdat } 
    } }
  },
  { 
    State::HDAT,
    State{ {
      { Chunk::HHDR, hdat_got_hhdr },
      { Chunk::RHDR, hdat_got_rhdr },
      { Chunk::SDAT, hdat_got_sdat },
      { Chunk::FEND, hdat_got_fend }
    } }
  },
  {
    State::RHDR,
    State{ {
      { Chunk::RHFD, rhdr_got_rhfd },
      { Chunk::RSFD, rhdr_got_rsfd }
    } }
  },
  {
    State::RHFD,
    State{ {
      { Chunk::RHFD, rhfd_got_rhfd },
      { Chunk::RSFD, rhfd_got_rsfd },
      { Chunk::RDAT, rhfd_got_rdat }
    } }
  },
  {
    State::RSFD,
    State{ {
      { Chunk::RHFD, rsfd_got_rhfd },
      { Chunk::RDAT, rsfd_got_rdat }
    } }
  },
  {
    State::RSFD,
    State{ {
      { Chunk::RHFD, rsfd_got_rhfd },
      { Chunk::RDAT, rsfd_got_rdat }
    } }
  },
  {
    State::RDAT,
    State{ {
      { Chunk::HHDR, rdat_got_hhdr },
      { Chunk::RHDR, rdat_got_rhdr },
      { Chunk::SDAT, rdat_got_sdat },
      { Chunk::FEND, rdat_got_fend }
    } }
  },
  {
    State::SDAT,
    State{ {
      { Chunk::HHDR, sdat_got_hhdr },
      { Chunk::RHDR, sdat_got_rhdr },
      { Chunk::FEND, sdat_got_fend }
    } }
  }
};

// TODO: add validation flag

/*
class ChunkReader {
public:

private:
  bool verbose;


};
*/

void read_chunks(const char* beg, const char* end) {

  const char* pos = beg + 8;  // TODO: don't skip magic 
  State::Type state = State::INIT;

  Holder h;

  while (state != State::FEND) {
    const State& st = SMAP.at(state);
    const Chunk ch = decode_chunk(beg, pos, end);
  
    const auto i = st.allowed.find(ch.type);
    THROW_IF(
      i == st.allowed.end(), 
      "unexpected chunk type " << to_hex(&ch.type, &ch.type + sizeof(ch.type))
    );
    state = (i->second)(ch, h);
  }

  THROW_IF(pos != end, "found more data after FEND chunk");
}
