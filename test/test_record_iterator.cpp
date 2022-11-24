#include "hashset/record_iterator.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <numeric>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("RecordProxy_swap") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x22, 0x22,
    0x11, 0x11
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  std::swap(a, b);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));
}

TEST_CASE("RecordProxy_copy_assignment") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x22, 0x22,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  a = b;

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp, rlen));
}

TEST_CASE("RecordProxy_copy_ctor") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy b{{dat + rlen, rlen}};
  RecordProxy a(b);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp + rlen, rlen));
}

TEST_CASE("RecordProxy_move_assignment") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x22, 0x22,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  a = std::move(b);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp, rlen));
}

TEST_CASE("RecordProxy_move_ctor") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy b{{dat + rlen, rlen}};
  RecordProxy a(std::move(b));

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp + rlen, rlen));
  CHECK(a.rec.data() != exp);
}

TEST_CASE("RecordProxy_cmp") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  CHECK(a < b);
  CHECK(a <= b);
  CHECK(!(a == b));
  CHECK(a != b);
  CHECK(b >= a);
  CHECK(b > a);

  CHECK(!(a < a));
  CHECK(a <= a);
  CHECK(a == a);
  CHECK(!(a != a));
  CHECK(a >= a);
  CHECK(!(a > a));
}

template <class Itr>
void check_weakly_incrementable(Itr a) {
  CHECK(std::addressof(++a) == std::addressof(a));
}

template <class Itr>
void check_forward_iterator_1(Itr a, Itr b) {
// only if a, b are dereferenceable
  CHECKED_IF(a == b) {
    CHECK(++a == ++b);
  }
}

template <class Itr>
void check_forward_iterator_2(Itr a) {
// only if a is dereferenceable
  CHECK(((void)[](auto x){ ++x; }(a), *a) == *a);
}

template <class Itr>
void check_bidirectional_iterator_1(Itr a) {
// a is incrementable
  CHECK(std::addressof(--a) == std::addressof(a));
}

template <class Itr>
void check_bidirectional_iterator_2(Itr a) {
// a is decrementable
  Itr b = a;
  CHECK(a-- == b);
}

template <class Itr>
void check_bidirectional_iterator_3(Itr a) {
  Itr b = a;
  CHECK(a-- == b--);
}

template <class Itr>
void check_bidirectional_iterator_4(Itr a) {
  Itr b = a;
  CHECK(--(++a) == b);
}

template <class Itr>
void check_bidirectional_iterator_5(Itr a) {
  Itr b = a;
  CHECK(++(--a) == b);
}

template <class Itr>
void check_random_access_iterator_1(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK((a += n) == b);
}

template <class Itr>
void check_random_access_iterator_2(Itr a, typename Itr::difference_type n) {
  CHECK(std::addressof(a += n) == std::addressof(a));
}

template <class Itr>
void check_random_access_iterator_3(Itr a, typename Itr::difference_type n) {
  Itr b = a + n;
  CHECK(b == (a += n));
}

template <class Itr>
void check_random_access_iterator_4(Itr a, typename Itr::difference_type n) {
  CHECK(a + n == n + a);
}

template <class Itr>
void check_random_access_iterator_5(Itr a, typename Itr::difference_type x, typename Itr::difference_type y) {
  CHECK(a + (x + y) == (a + x) + y);
}

template <class Itr>
void check_random_access_iterator_6(Itr a) {
  CHECK(a + 0 == a);
}

template <class Itr>
void check_random_access_iterator_7(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK(a + (n - 1) == --b);
}

template <class Itr>
void check_random_access_iterator_8(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK((b += -n) == a);
}

template <class Itr>
void check_random_access_iterator_9(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK((b -= n) == a);
}

template <class Itr>
void check_random_access_iterator_10(Itr b, typename Itr::difference_type n) {
  CHECK(std::addressof(b -= n) == std::addressof(b));
}

template <class Itr>
void check_random_access_iterator_11(Itr b, typename Itr::difference_type n) {
  Itr a = b - n;
  CHECK(a == (b -= n));
}

template <class Itr>
void check_random_access_iterator_12(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK(a[n] == *b);
}

template <class Itr>
void check_random_access_iterator_13(Itr a, Itr b) {
  CHECK(a <= b);
}

TEST_CASE("RecordIterator_random_access_iterator") {

  uint8_t data[] = {
    0x10, 0x01,
    0x20, 0x02,
    0x30, 0x03,
    0x40, 0x04,
    0x50, 0x05
  };

  const size_t rlen = 2;

  const ssize_t rcount = std::size(data) / rlen;

  for (size_t ai = 0; ai < std::size(data); ++ai) {
    RecordIterator a(data + ai, rlen);

    check_weakly_incrementable(a);

    check_forward_iterator_2(a);

    check_bidirectional_iterator_1(a);
    check_bidirectional_iterator_2(a);
    check_bidirectional_iterator_3(a);
    check_bidirectional_iterator_4(a);
    check_bidirectional_iterator_5(a);

    check_random_access_iterator_6(a);

    for (size_t bi = 0; bi < std::size(data); ++bi) {
      RecordIterator b(data + bi, rlen);
      check_forward_iterator_1(a, b);
    }

    for (RecordIterator::difference_type x = -rcount; x < rcount; ++x) {
      for (RecordIterator::difference_type y = -rcount; y < rcount; ++y) {
        check_random_access_iterator_5(a, x, y);
      }
    }

    for (RecordIterator::difference_type n = -rcount; n < rcount; ++n) {
      RecordIterator b = a + n;

      check_random_access_iterator_1(a, b, n);
      check_random_access_iterator_2(a, n);
      check_random_access_iterator_3(a, n);
      check_random_access_iterator_4(a, n);

      check_random_access_iterator_7(a, b, n);
      check_random_access_iterator_8(a, b, n);
      check_random_access_iterator_9(a, b, n);
      check_random_access_iterator_10(b, n);

      check_random_access_iterator_11(b, n);
      check_random_access_iterator_12(a, b, n);

      if (n >= 0) {
        check_random_access_iterator_13(a, b);
      }
    }
  }
}

TEST_CASE("RecordIterator_sort_small") {
  uint8_t dat[] = {
    0x33, 0x33,
    0x22, 0x22,
    0x11, 0x11
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22,
    0x33, 0x33
  };

  const size_t rlen = 2;
  const size_t rcount = std::size(dat) / rlen;

  RecordIterator beg(std::begin(dat), rlen);
  RecordIterator end(std::end(dat), rlen);

  std::sort(beg, end);

  for (size_t i = 0; i < rcount; ++i) {
    CHECK(!std::memcmp(dat + i*rlen, exp + i*rlen, rlen));
  }
}

TEST_CASE("RecordIterator_sort_large") {
/*
  uint8_t dat[1000];

  const size_t rlen = 2;
  const size_t rcount = std::size(dat) / rlen;

  std::iota(
    std::reverse_iterator(reinterpret_cast<uint16_t*>(std::end(dat))),
    std::reverse_iterator(reinterpret_cast<uint16_t*>(std::begin(dat))),
    0
  );

  uint8_t exp[1000];
  std::iota(
    reinterpret_cast<uint16_t*>(std::begin(exp)),
    reinterpret_cast<uint16_t*>(std::end(exp)),
    0
  );

  RecordIterator beg(std::begin(dat), rlen);
  RecordIterator end(std::end(dat), rlen);

  std::sort(beg, end);

  for (size_t i = 0; i < rcount; ++i) {
    CHECK(!std::memcmp(dat + i*rlen, exp + i*rlen, rlen));
  }
*/
}

TEST_CASE("RecordIterator_unique") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x11, 0x11,
    0x11, 0x11,
    0x11, 0x11,
    0x11, 0x11,
    0x22, 0x22,
    0x33, 0x33,
    0x33, 0x33
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22,
    0x33, 0x33
  };

  const size_t rlen = 2;

  RecordIterator beg(std::begin(dat), rlen);
  RecordIterator end(std::end(dat), rlen);

  RecordIterator nend = std::unique(beg, end);

  CHECK(nend - beg == std::size(exp) / rlen);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));
  CHECK(!std::memcmp(dat + 2*rlen, exp + 2*rlen, rlen));
}
