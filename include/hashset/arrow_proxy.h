#pragma once

template <class Reference>
struct ArrowProxy {
  Reference r;

  Reference* operator->() {
    return &r;
  }
};
