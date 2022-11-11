#include "hashset/hset_structs.h"

#include <ostream>

std::ostream& operator<<(std::ostream& out, const TableOfContents& ftoc) {
  out << "FTOC\n";
  for (const auto [off, type]: ftoc.entries) {
    out << off << ' ' << type << '\n';
  }
  return out;
}

std::ostream& operator<<(std::ostream& out, const FileHeader& fhdr) {
  return out << "FHDR\n"
             << ' ' << fhdr.version << '\n'
             << ' ' << fhdr.name << '\n'
             << ' ' << fhdr.desc << '\n'
             << ' ' << fhdr.time;
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

std::ostream& operator<<(std::ostream& out, const HashsetData& hdat) {
  return out << "HDAT\n"
             << ' ' << hdat.beg << '\n'
             << ' ' << hdat.end;
}

std::ostream& operator<<(std::ostream& out, const RecordIndex& ridx) {
  return out << "RIDX\n"
             << ' ' << ridx.beg << '\n'
             << ' ' << ridx.end;
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

std::ostream& operator<<(std::ostream& out, const RecordData& rdat) {
  return out << "RDAT\n"
             << ' ' << rdat.beg << '\n'
             << ' ' << rdat.end;
}
