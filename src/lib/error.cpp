#include "hasher/common.h"
#include "error.h"

#include <cstring>

using Error = SFHASH_Error;

void fill_error(Error** err, const std::string& msg) {
  *err = new Error;
  (*err)->message = new char[msg.length()+1];
  std::strcpy((*err)->message, msg.c_str());
}

void sfhash_free_error(Error* err) {
  if (err) {
    delete[] err->message;
    delete err;
  }
}
