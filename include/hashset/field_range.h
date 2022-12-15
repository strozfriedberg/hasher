#pragma once

#include <cstdint>
#include <ranges>
#include <utility>
#include <vector>

#include "hashset/field_iterator.h"

template <class Columns>
class FieldRange {
public:
  FieldRange(
    const Columns& cols,
    const std::vector<std::pair<void (*)(uint8_t* dst, const char* src, size_t dlen), size_t>>& conv
  ): cols(cols), conv(conv) {}

  auto begin() const {
    return FieldIterator(std::ranges::begin(cols), std::ranges::begin(conv));
  }

  auto end() const {
    return FieldIterator(std::ranges::end(cols), std::ranges::end(conv));
  }

private:
  const Columns& cols;
  const std::vector<std::pair<void (*)(uint8_t* dst, const char* src, size_t dlen), size_t>>& conv;
};
