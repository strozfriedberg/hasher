#include "entropy.h"
#include "entropy_impl.h"

#include <algorithm>
#include <cmath>
#include <iterator>
#include <numeric>


SFHASH_Entropy* sfhash_create_entropy() {
  return new SFHASH_Entropy();
}

SFHASH_Entropy* sfhash_clone_entropy(const SFHASH_Entropy* entropy) {
  return new SFHASH_Entropy(*entropy);
}

void sfhash_update_entropy(SFHASH_Entropy* entropy, const void* beg, const void* end) {
  for (const uint8_t* cur = static_cast<const uint8_t*>(beg); cur != static_cast<const uint8_t*>(end); ++cur) {
    ++entropy->hist[*cur];
  } 
}

double sfhash_get_entropy(SFHASH_Entropy* entropy) {
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
    std::begin(entropy->hist),
    std::end(entropy->hist),
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
    std::begin(entropy->hist),
    std::end(entropy->hist),
    0.0,
    [](double a, double b) {
      return a + (b ? b * std::log2(b) : 0.0);
    }
  ) / s : 0.0;
}

void sfhash_accumulate_entropy(SFHASH_Entropy* sum, const SFHASH_Entropy* addend) {
  std::transform(
    std::begin(sum->hist), std::end(sum->hist),
    std::begin(addend->hist),
    std::begin(sum->hist),
    [](uint64_t a, uint64_t b) { return a + b; }
  );
}

void sfhash_reset_entropy(SFHASH_Entropy* entropy) {
  std::fill(std::begin(entropy->hist), std::end(entropy->hist), 0);
}

void sfhash_destroy_entropy(SFHASH_Entropy* entropy) {
  delete entropy;
}
