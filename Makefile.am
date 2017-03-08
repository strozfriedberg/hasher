ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/include $(PROJECT_CPPFLAGS)
AM_CXXFLAGS = $(PROJECT_CXXFLAGS)
AM_LDFLAGS = $(PROJECT_LDFLAGS)

src_hasher_SOURCES = \
	src/main.cpp \
	src/hasher.cpp

src_hasher_LDADD = $(PROJECT_LIBS)

noinst_PROGRAMS = src/hasher

check_PROGRAMS = test/test

TESTS = $(check_PROGRAMS)

test_test_SOURCES = \
	src/hasher.cpp \
	test/test.cpp \
	test/test_hasher.cpp

test_test_CPPFLAGS = $(AM_CPPFLAGS) $(SCOPE_CPPFLAGS)
