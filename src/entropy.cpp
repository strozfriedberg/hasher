#include "entropy_impl.h"

#include <algorithm>
#include <cmath>
#include <iterator>
#include <numeric>

void EntropyCalculator::update(const uint8_t* beg, const uint8_t* end) {
  for (const uint8_t* cur = beg; cur != end; ++cur) {
    ++Hist[*cur];
  }
}

void EntropyCalculator::get(void* val) {
  *static_cast<double*>(val) = entropy();
}

double EntropyCalculator::entropy() const {
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

  const uint64_t s = std::accumulate(std::begin(Hist), std::end(Hist), UINT64_C(0));

  // Sligtly optimized computation
  if (s) {
    double sum = std::accumulate(std::begin(Hist), std::end(Hist), 0.0, [](double a, double b) {
      return a + (b ? b * std::log2(b) : 0.0);
    });
    return std::log2(static_cast<double>(s)) - (sum / s);
  }
  return 0.0;
}

void EntropyCalculator::reset() {
  std::fill(std::begin(Hist), std::end(Hist), 0);
}

EntropyCalculator* EntropyCalculator::clone() const {
  return new EntropyCalculator(*this);
}

std::unique_ptr<HasherImpl> make_entropy_calculator() {
  return std::unique_ptr<EntropyCalculator>(new EntropyCalculator());
}
