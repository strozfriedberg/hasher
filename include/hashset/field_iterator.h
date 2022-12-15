#pragma once

#include <cstdint>
#include <iterator>
#include <span>
#include <utility>
#include <vector>

#include "hashset/arrow_proxy.h"

template <class ColumnsItr>
class FieldIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = std::span<uint8_t>;
  using reference = value_type;
  using pointer = ArrowProxy<reference>;
  using difference_type = std::ptrdiff_t;

  FieldIterator(
    ColumnsItr cols_itr,
    std::vector<std::pair<void (*)(uint8_t* dst, const char* src, size_t dlen), size_t>>::const_iterator conv_itr
  ): cols_itr(cols_itr), conv_itr(conv_itr), good(false) {
  }

  FieldIterator(): good(false) {}

  reference operator*() {
    populate();
    return {rec};
  }

  pointer operator->() {
    populate();
    return pointer{{rec}};
  }

  FieldIterator& operator++() {
    ++cols_itr;
    ++conv_itr;
    good = false;

    return *this;
  }

  FieldIterator operator++(int) {
    FieldIterator itr{*this};
    ++(*this);
    return itr;
  }

  bool operator==(const FieldIterator& other) const {
    return cols_itr == other.cols_itr;
  }

  bool operator!=(const FieldIterator& other) const {
    return cols_itr == other.cols_itr;
  }

private:
  void populate() {
    if (!good) {
      rec.resize(conv_itr->second);
      conv_itr->first(rec.data(), cols_itr->data(), conv_itr->second);
      good = true;
    }
  }

  ColumnsItr cols_itr;
  std::vector<std::pair<void (*)(uint8_t* dst, const char* src, size_t dlen), size_t>>::const_iterator conv_itr;

  std::vector<uint8_t> rec;
  bool good;
};
