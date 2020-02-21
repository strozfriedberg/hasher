#include "hasher/api.h"
#include "util.h"

#include <lightgrep/api.h>

#include <cstring>
#include <sstream>

void fill_error(SFHASH_Error** err, const std::string& msg) {
  *err = new SFHASH_Error;
  (*err)->message = new char[msg.length()+1];
  std::strcpy((*err)->message, msg.c_str());
}

void fill_error(SFHASH_Error** err, const LG_Error* lg_err) {
  std::ostringstream os;

  while (lg_err) {
    if (lg_err->Message) {
      os << lg_err->Message;
      if (lg_err->Pattern) {
        os << ": " << lg_err->Pattern;
        if (lg_err->EncodingChain) {
          os << ": " << lg_err->EncodingChain;
        }
        if (lg_err->Source) {
          os << ": " << lg_err->Source;
        }
        os << ": " << lg_err->Index;
      }
    }
    lg_err = lg_err->Next;
  }

  fill_error(err, os.str());
}
