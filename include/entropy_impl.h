#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <memory>
#include <numeric>

#include "hasher_impl.h"

struct SFHASH_Entropy {
  uint64_t hist[256] = {0};
};


class EntropyCalculator: public HasherImpl {
public:
  virtual ~EntropyCalculator() {}

  virtual void update(const uint8_t* beg, const uint8_t* end) {
    for (const uint8_t* cur = beg; cur != end; ++cur) {
      ++hist[*cur];
    }
  }

  virtual void get(void* val) {
    *static_cast<double*>(val) = entropy();
  }

  double entropy() const {
    /*
      Shannon entropy of A:

        H(A) = -\Sigma^n_{i=0} p_i \log_2 p_i

      where p_i is the probability with which element i occurs in A.
      For bytes, p_i = b_i / s, where b_i is the count of occurances of
      byte i and s is the total number of bytes. So:

        H(A) = -\Sigma^n_{i=0} b_i/s \log_2 b_i/s

      A bit of rearranging yields:

        H(A) = \log_2 s - (\Sigma^n_{i=0} b_i \log_2 b_i) / s

      We use the latter for computation as it trades one additional call to
      log2() for 255 fewer floating point divisions, so should accumulate
      less error than direct computation from the definition.
    */

    const uint64_t s = std::accumulate(
      std::begin(hist),
      std::end(hist),
      UINT64_C(0)
    );

/*
    // Direct computation from the definition
    return s ? -std::accumulate(
      std::begin(entropy->hist),
      std::end(entropy->hist),
      0.0,
      [s](double a, double b) {
        const double p_i = b/s;
        return a + (p_i ? p_i * std::log2(p_i) : 0.0);
      }
    ) : 0.0;
*/

    // Sligtly optimized computation
    return s ? std::log2(static_cast<double>(s)) - std::accumulate(
      std::begin(hist),
      std::end(hist),
      0.0,
      [](double a, double b) {
        return a + (b ? b * std::log2(b) : 0.0);
      }
    ) / s : 0.0;
  }

  virtual void reset() {
    std::fill(std::begin(hist), std::end(hist), 0);
  }

  virtual EntropyCalculator* clone() const {
    return new EntropyCalculator(*this);
  }

private:
  uint64_t hist[256] = {0};
};

inline std::unique_ptr<HasherImpl> make_entropy_calculator() {
  return std::unique_ptr<EntropyCalculator>(new EntropyCalculator());
}
