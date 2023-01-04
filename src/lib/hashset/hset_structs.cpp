#include "hashset/hset_structs.h"

#include "hex.h"
#include "rwutil.h"

#include <iomanip>
#include <ostream>

std::ostream& operator<<(std::ostream& out, const TableOfContents& ftoc) {
  out << "FTOC\n";
  for (const auto [off, type]: ftoc.entries) {
    out << off << ' '
        << std::hex << std::setw(8) << std::setfill('0')
        << type
        << std::dec << std::setw(0) << std::setfill(' ') << '\n';
  }
  return out;
}

std::ostream& operator<<(std::ostream& out, const FileHeader& fhdr) {
  return out << "FHDR\n"
             << ' ' << fhdr.version << '\n'
             << ' ' << fhdr.name << '\n'
             << ' ' << fhdr.desc << '\n'
             << ' ' << fhdr.time << '\n'
             << ' ' << to_hex(fhdr.sha2_256);
}

std::ostream& operator<<(std::ostream& out, const HashsetHeader& hhdr) {
  return out << "HHDR\n"
             << ' ' << hhdr.hash_type << '\n'
             << ' ' << hhdr.hash_name << '\n'
             << ' ' << hhdr.hash_length << '\n'
             << ' ' << hhdr.hash_count;
}

std::ostream& operator<<(std::ostream& out, const HashsetHint& hint) {
  return out << "HINT\n"
             << ' ' << hint.hint_type << '\n'
             << ' ' << hint.beg << '\n'
             << ' ' << hint.end;
}

template <class HDAT>
std::ostream& out_hdat(std::ostream& out, const HDAT& hdat) {
  return out << "HDAT\n"
             << ' ' << hdat.beg << '\n'
             << ' ' << hdat.end;
}

std::ostream& operator<<(std::ostream& out, const HashsetData& hdat) {
  return out_hdat(out, hdat);
}

std::ostream& operator<<(std::ostream& out, const ConstHashsetData& hdat) {
  return out_hdat(out, hdat);
}

template <class RIDX>
std::ostream& out_ridx(std::ostream& out, const RIDX& ridx) {
  return out << "RIDX\n"
             << ' ' << ridx.beg << '\n'
             << ' ' << ridx.end;
}

std::ostream& operator<<(std::ostream& out, const RecordIndex& ridx) {
  return out_ridx(out, ridx);
}

std::ostream& operator<<(std::ostream& out, const ConstRecordIndex& ridx) {
  return out_ridx(out, ridx);
}

std::ostream& operator<<(std::ostream& out, const RecordFieldDescriptor& rfd) {
  return out << "RFD\n"
             << ' ' << rfd.type << '\n'
             << ' ' << rfd.name << '\n'
             << ' ' << rfd.length;
}

std::ostream& operator<<(std::ostream& out, const RecordHeader& rhdr) {
  out << "RHDR\n"
      << ' ' << rhdr.record_length << '\n'
      << ' ' << rhdr.record_count << '\n';

  for (const auto& f: rhdr.fields) {
    out << f << '\n';
  }

  return out;
}

template <class RDAT>
std::ostream& out_rdat(std::ostream& out, const RDAT& rdat) {
  return out << "RDAT\n"
             << ' ' << rdat.beg << '\n'
             << ' ' << rdat.end;
}

std::ostream& operator<<(std::ostream& out, const RecordData& rdat) {
  return out_rdat(out, rdat);
}

std::ostream& operator<<(std::ostream& out, const ConstRecordData& rdat) {
  return out_rdat(out, rdat);
}

std::string printable_chunk_type(uint32_t type) {
  const uint32_t t = to_be(type);
  const char* tt = reinterpret_cast<const char*>(&t);

  if (tt[0] == 'H' && tt[1] == 'H') {
    return "HH " + to_hex(tt + 2, tt + 4);
  }
  else {
    return std::string(tt, tt + 4);
  }
}
