ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/include $(PROJECT_CPPFLAGS)
AM_CXXFLAGS = $(PROJECT_CXXFLAGS)
AM_LDFLAGS = $(PROJECT_LDFLAGS)

HASHER_LIB = src/libhasher.la
HASHER_LIB_INT = src/libhasherint.la

lib_LTLIBRARIES = $(HASHER_LIB)

#if BUILD_DLL
#src_libhasher_la_SOURCES = src/version.rc
#else
src_libhasher_la_SOURCES =
#endif
nodist_EXTRA_src_libhasher_la_SOURCES = dummy.cpp # forces C++ linking

noinst_LTLIBRARIES = $(HASHER_LIB_INT)

src_libhasherint_la_SOURCES = \
	src/entropy.cpp \
	src/error.cpp \
	src/fuzzy_hasher.cpp \
	src/fuzzy_matcher.cpp \
	src/hash_types.cpp \
	src/hasher.cpp \
	src/hashset.cpp \
	src/hashsetdata.cpp \
	src/hashsetinfo.cpp \
	src/hex.cpp \
	src/libblake3_hasher.cpp \
	src/libcrypto_hasher.cpp \
	src/matcher.cpp \
	src/parser.cpp \
	src/quick_hasher.cpp \
	src/sizeset.cpp \
	src/util.cpp

src_libhasher_la_LIBADD = $(HASHER_LIB_INT) $(PROJECT_LIBS)
if BUILD_DLL
src_libhasher_la_LDFLAGS = $(AM_LDFLAGS) $(HASHER_LIB_LDFLAGS) -avoid-version
else
src_libhasher_la_LDFLAGS = $(AM_LDFLAGS) $(HASHER_LIB_LDFLAGS)
endif

src_libhasher_ladir = $(includedir)

src_libhasher_la_HEADERS = \
	include/hasher/api.h

src_fuzzy_SOURCES = \
        src/fuzzy_main.cpp

src_fuzzy_LDADD = $(HASHER_LIB) $(PROJECT_LIBS) $(BOOST_FILESYSTEM_LIB) $(BOOST_SYSTEM_LIB)

src_hasher_SOURCES = \
	src/hasher_main.cpp

src_hasher_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)

src_matcher_SOURCES = \
	src/matcher_main.cpp

src_matcher_LDADD = $(HASHER_LIB) $(PROJECT_LIBS) $(BOOST_FILESYSTEM_LIB) $(BOOST_SYSTEM_LIB)

bin_PROGRAMS = src/fuzzy src/hasher src/matcher

check_PROGRAMS = test/test
TESTS = \
	$(check_PROGRAMS) \
	python/test.sh

test_test_SOURCES = \
	test/test.cpp \
	test/test_entropy.cpp \
	test/test_fuzzy_matcher.cpp \
	test/test_hasher.cpp \
	test/test_hashsetdata.cpp \
	test/test_hashset_setops.cpp \
	test/test_hex.cpp \
	test/test_matcher.cpp \
	test/test_parser.cpp \
	test/test_util.cpp

test_test_CPPFLAGS = $(AM_CPPFLAGS) $(SCOPE_CPPFLAGS)

test_test_LDADD = $(HASHER_LIB) $(TEST_LIBS)

FORMAT_COMMAND := tools/git-clang-format -f --style=file

format:
	@echo "[+] clang-format (`which clang-format`) version: `clang-format --version`"
	@$(FORMAT_COMMAND)

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = src/hasher.pc

src/hasher.pc: src/hasher.pc.in Makefile
	sed -e 's![@]prefix[@]!$(prefix)!g' \
      -e 's![@]exec_prefix[@]!$(exec_prefix)!g' \
      -e 's![@]includedir[@]!$(includedir)!g' \
      -e 's![@]libdir[@]!$(libdir)!g' \
      -e 's![@]PACKAGE_VERSION[@]!$(PACKAGE_VERSION)!g' \
      $< >$@

CLEANFILES = src/hasher.pc

install-exec-hook:
	$(RM) $(DESTDIR)$(libdir)/libhasher.la
