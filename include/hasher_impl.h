#pragma once

#include <cstdint>

class HasherImpl {
public:
  /*
    HasherImpl(const HasherImpl& other)
    {
  // clone
    }

    HasherImpl(HasherImpl&& other)
    {
  // clone
    }

    HasherImpl& operator=(const HasherImpl& other) {
  //    return *this;
    }

    HasherImpl& operator=(HasherImpl&& other) {
  //    return *this;
    }
  */

  virtual ~HasherImpl() {}

  virtual void update(const uint8_t* beg, const uint8_t* end) = 0;

  virtual void set_total_input_length(uint64_t len) = 0;

  virtual void get(void* val) = 0;

  virtual void reset() = 0;

  virtual HasherImpl* clone() const = 0;
};
