#include "hasher/api.h"
#include "error.h"

#include <lightgrep/api.h>

#include <cstring>
#include <sstream>

using Error = SFHASH_Error;

void fill_error(Error** err, const std::string& msg) {
  *err = new Error;
  (*err)->message = new char[msg.length()+1];
  std::strcpy((*err)->message, msg.c_str());
}

void fill_error(Error** err, const LG_Error* lg_err) {
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

void sfhash_free_error(Error* err) {
  if (err) {
    delete[] err->message;
    delete err;
  }
}
