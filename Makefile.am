ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/include $(PROJECT_CPPFLAGS)
AM_CXXFLAGS = $(PROJECT_CXXFLAGS)
AM_LDFLAGS = $(PROJECT_LDFLAGS)

HASHER_LIB = src/libhasher.la
HASHER_LIB_INT = src/libhasherint.la

lib_LTLIBRARIES = $(HASHER_LIB)

src_libhasher_la_SOURCES =
nodist_EXTRA_src_libhasher_la_SOURCES = dummy.cpp # forces C++ linking

noinst_LTLIBRARIES = $(HASHER_LIB_INT)

src_libhasherint_la_SOURCES = \
	src/hasher.cpp \
	src/matcher.cpp

src_libhasher_la_LIBADD = $(HASHER_LIB_INT) $(PROJECT_LIBS)

src_libhasher_la_LDFLAGS = $(AM_LDFLAGS) $(HASHER_LIB_LDFLAGS)

src_libhasher_ladir = $(includedir)

src_libhasher_la_HEADERS = \
	include/hasher.h

src_hasher_SOURCES = \
	src/main.cpp

src_hasher_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)

noinst_PROGRAMS = src/hasher

check_PROGRAMS = test/test
TESTS = $(check_PROGRAMS)

test_test_SOURCES = \
	test/test.cpp \
	test/test_hasher.cpp

test_test_CPPFLAGS = $(AM_CPPFLAGS) $(SCOPE_CPPFLAGS)

test_test_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)
