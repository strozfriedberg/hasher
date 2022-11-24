ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/vendors/parallel-hashmap $(PROJECT_CPPFLAGS)
AM_CXXFLAGS = $(PROJECT_CXXFLAGS)
AM_LDFLAGS = $(PROJECT_LDFLAGS)

HASHER_LIB = src/lib/libhasher.la
HASHER_LIB_INT = src/lib/libhasherint.la
BLAKE3_LIB_INT = vendors/BLAKE3/c/libblake3int.la

lib_LTLIBRARIES = $(HASHER_LIB)

#if BUILD_DLL
#src_lib_libhasher_la_SOURCES = src/lib/version.rc
#else
src_lib_libhasher_la_SOURCES =
#endif
nodist_EXTRA_src_lib_libhasher_la_SOURCES = dummy.cpp # forces C++ linking

noinst_LTLIBRARIES = $(HASHER_LIB_INT) $(BLAKE3_LIB_INT)

src_lib_libhasherint_la_SOURCES = \
	src/lib/error.cpp \
	src/lib/fuzzy_matcher.cpp \
	src/lib/hash_types.cpp \
	src/lib/hashsetinfo.cpp \
	src/lib/parser.cpp \
	src/lib/rwutil.cpp \
	src/lib/util.cpp \
	src/lib/hasher/entropy.cpp \
	src/lib/hasher/fuzzy_hasher.cpp \
	src/lib/hasher/hasher.cpp \
	src/lib/hasher/libblake3_hasher.cpp \
	src/lib/hasher/libcrypto_hasher.cpp \
	src/lib/hasher/quick_hasher.cpp \
	src/lib/hashset/convex_hull.cpp \
	src/lib/hashset/hset.cpp \
	src/lib/hashset/hset_decoder.cpp \
	src/lib/hashset/hset_encoder.cpp \
	src/lib/hashset/hset_ops.cpp \
	src/lib/hashset/hset_structs.cpp \
	src/lib/hashset/record_iterator.cpp \
	src/lib/hashset/util.cpp \
	src/lib/hex/hex.cpp \
	src/lib/hex/hex_avx2.cpp \
	src/lib/hex/hex_sse41.cpp

src_lib_libhasher_la_LIBADD = $(HASHER_LIB_INT) $(BLAKE3_LIB_INT) $(PROJECT_LIBS)
if BUILD_DLL
src_lib_libhasher_la_LDFLAGS = $(AM_LDFLAGS) $(HASHER_LIB_LDFLAGS) -avoid-version
else
src_lib_libhasher_la_LDFLAGS = $(AM_LDFLAGS) $(HASHER_LIB_LDFLAGS)
endif

src_lib_libhasher_ladir = $(includedir)/hasher

src_lib_libhasher_la_HEADERS = \
	include/hasher/api.h \
	include/hasher/common.h \
	include/hasher/fuzzy.h \
	include/hasher/hasher.h \
	include/hasher/hashset.h \
	include/hasher/hex.h

vendors_BLAKE3_c_libblake3int_la_CPPFLAGS = $(AM_CPPFLAGS)

vendors_BLAKE3_c_libblake3int_la_SOURCES = \
	vendors/BLAKE3/c/blake3.c \
	vendors/BLAKE3/c/blake3_dispatch.c \
	vendors/BLAKE3/c/blake3_portable.c

if HOST_X86_64

if HOST_WINDOWS
vendors_BLAKE3_c_libblake3int_la_SOURCES += \
	vendors/BLAKE3/c/blake3_sse2_x86-64_windows_gnu.S \
	vendors/BLAKE3/c/blake3_sse41_x86-64_windows_gnu.S \
	vendors/BLAKE3/c/blake3_avx2_x86-64_windows_gnu.S \
	vendors/BLAKE3/c/blake3_avx512_x86-64_windows_gnu.S
else
vendors_BLAKE3_c_libblake3int_la_SOURCES += \
	vendors/BLAKE3/c/blake3_sse2_x86-64_unix.S \
	vendors/BLAKE3/c/blake3_sse41_x86-64_unix.S \
	vendors/BLAKE3/c/blake3_avx2_x86-64_unix.S \
	vendors/BLAKE3/c/blake3_avx512_x86-64_unix.S
endif

endif

if HOST_ARM
vendors_BLAKE3_c_libblake3int_la_SOURCES += \
	vendors/BLAKE3/c/blake3_neon.c
endif

if HOST_NO_SIMD
vendors_BLAKE3_c_libblake3int_la_CPPFLAGS += -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512
endif

src_fuzzy_fuzzy_SOURCES = \
	src/fuzzy/fuzzy_main.cpp

src_fuzzy_fuzzy_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)

src_hasher_hasher_SOURCES = \
	src/hasher/hasher_main.cpp

src_hasher_hasher_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)

src_mkhashset_mkhashset_SOURCES = \
	src/mkhashset/mkhashset_main.cpp

src_mkhashset_mkhashset_LDADD = $(HASHER_LIB) $(PROJECT_LIBS)

bin_PROGRAMS = src/fuzzy/fuzzy src/hasher/hasher src/mkhashset/mkhashset

check_PROGRAMS = test/test

noinst_PROGRAMS = test/bench_hex test/bench_hsd

TESTS = \
	$(check_PROGRAMS) \
	python/test.sh

test_test_SOURCES = \
	test/helper.cpp \
	test/test_convex_hull.cpp \
	test/test_entropy.cpp \
	test/test_fuzzy_matcher.cpp \
	test/test_hasher.cpp \
	test/test_hashset_api.cpp \
	test/test_hashsetdata_util.cpp \
	test/test_hex.cpp \
	test/test_hset_decoder.cpp \
	test/test_hset_encoder.cpp \
	test/test_hset_ops.cpp \
	test/test_hset_round_trip.cpp \
	test/test_parser.cpp \
	test/test_util.cpp

test_test_CFLAGS = $(AM_CFLAGS) $(CATCH2_CFLAGS)

test_test_LDADD = $(HASHER_LIB) $(TEST_LIBS) $(CATCH2_LIBS)

test_bench_hex_SOURCES = \
	test/bench_hex.cpp

test_bench_hex_CFLAGS = $(AM_CFLAGS) $(CATCH2_CFLAGS)
test_bench_hex_LDADD = $(HASHER_LIB) $(TEST_LIBS) $(CATCH2_LIBS)

test_bench_hsd_SOURCES = \
	test/bench_hsd_lookup.cpp

test_bench_hsd_CFLAGS = $(AM_CFLAGS) $(CATCH2_CFLAGS)
test_bench_hsd_LDADD = $(HASHER_LIB) $(TEST_LIBS) $(CATCH2_LIBS)

FORMAT_COMMAND := tools/git-clang-format -f --style=file

format:
	@echo "[+] clang-format (`which clang-format`) version: `clang-format --version`"
	@$(FORMAT_COMMAND)

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = src/lib/hasher.pc

src/lib/hasher.pc: src/lib/hasher.pc.in Makefile
	sed -e 's![@]prefix[@]!$(prefix)!g' \
      -e 's![@]exec_prefix[@]!$(exec_prefix)!g' \
      -e 's![@]includedir[@]!$(includedir)!g' \
      -e 's![@]libdir[@]!$(libdir)!g' \
      -e 's![@]PACKAGE_VERSION[@]!$(PACKAGE_VERSION)!g' \
      $< >$@

CLEANFILES = src/lib/hasher.pc

install-exec-hook:
	$(RM) $(DESTDIR)$(libdir)/lib/libhasher.la
