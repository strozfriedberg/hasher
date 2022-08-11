ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/vendors/parallel-hashmap $(PROJECT_CPPFLAGS)
AM_CXXFLAGS = $(PROJECT_CXXFLAGS)
AM_LDFLAGS = $(PROJECT_LDFLAGS)

HASHER_LIB = src/libhasher.la
HASHER_LIB_INT = src/libhasherint.la
BLAKE3_LIB_INT = vendors/BLAKE3/c/libblake3int.la

lib_LTLIBRARIES = $(HASHER_LIB)

#if BUILD_DLL
#src_libhasher_la_SOURCES = src/version.rc
#else
src_libhasher_la_SOURCES =
#endif
nodist_EXTRA_src_libhasher_la_SOURCES = dummy.cpp # forces C++ linking

noinst_LTLIBRARIES = $(HASHER_LIB_INT) $(BLAKE3_LIB_INT)

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
	src/hex_avx2.cpp \
	src/hex_sse41.cpp \
	src/libblake3_hasher.cpp \
	src/libcrypto_hasher.cpp \
	src/parser.cpp \
	src/quick_hasher.cpp \
	src/sizeset.cpp \
	src/util.cpp

src_libhasher_la_LIBADD = $(HASHER_LIB_INT) $(BLAKE3_LIB_INT) $(PROJECT_LIBS)
if BUILD_DLL
src_libhasher_la_LDFLAGS = $(AM_LDFLAGS) $(HASHER_LIB_LDFLAGS) -avoid-version
else
src_libhasher_la_LDFLAGS = $(AM_LDFLAGS) $(HASHER_LIB_LDFLAGS)
endif

src_libhasher_ladir = $(includedir)/hasher

src_libhasher_la_HEADERS = \
	include/hasher/api.h

vendors_BLAKE3_c_libblake3int_la_CPPFLAGS = $(AM_CPPFLAGS)

vendors_BLAKE3_c_libblake3int_la_SOURCES = \
	vendors/BLAKE3/c/blake3.c \
	vendors/BLAKE3/c/blake3_dispatch.c \
	vendors/BLAKE3/c/blake3_portable.c

if HOST_NO_SIMD
vendors_BLAKE3_c_libblake3int_la_CPPFLAGS += -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512
endif

if HOST_WINDOWS_X86_64
vendors_BLAKE3_c_libblake3int_la_SOURCES += \
	vendors/BLAKE3/c/blake3_sse2_x86-64_windows_gnu.S \
	vendors/BLAKE3/c/blake3_sse41_x86-64_windows_gnu.S \
	vendors/BLAKE3/c/blake3_avx2_x86-64_windows_gnu.S \
	vendors/BLAKE3/c/blake3_avx512_x86-64_windows_gnu.S
endif

if HOST_UNIX_X86_64
vendors_BLAKE3_c_libblake3int_la_SOURCES += \
	vendors/BLAKE3/c/blake3_sse2_x86-64_unix.S \
	vendors/BLAKE3/c/blake3_sse41_x86-64_unix.S \
	vendors/BLAKE3/c/blake3_avx2_x86-64_unix.S \
	vendors/BLAKE3/c/blake3_avx512_x86-64_unix.S
endif

if HOST_ARM
vendors_BLAKE3_c_libblake3int_la_SOURCES += \
	vendors/BLAKE3/c/blake3_neon.c
endif

src_fuzzy_SOURCES = \
	src/fuzzy_main.cpp

src_fuzzy_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)

src_hasher_SOURCES = \
	src/hasher_main.cpp

src_hasher_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)

bin_PROGRAMS = src/fuzzy src/hasher

check_PROGRAMS = test/test test/bench_hex

TESTS = \
	$(check_PROGRAMS) \
	python/test.sh

test_test_SOURCES = \
	test/test_entropy.cpp \
	test/test_fuzzy_matcher.cpp \
	test/test_hasher.cpp \
	test/test_hashset.cpp \
	test/test_hashset_setops.cpp \
	test/test_hex.cpp \
	test/test_parser.cpp \
	test/test_util.cpp

test_test_CFLAGS = $(AM_CFLAGS) $(CATCH2_CFLAGS)

test_test_LDADD = $(HASHER_LIB) $(TEST_LIBS) $(CATCH2_LIBS)

test_bench_hex_SOURCES = \
	test/bench_hex.cpp

test_bench_hex_CFLAGS = $(AM_CFLAGS) $(CATCH2_CFLAGS)
test_bench_hex_LDADD = $(HASHER_LIB) $(TEST_LIBS) $(CATCH2_LIBS)

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
