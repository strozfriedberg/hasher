__author__ = 'juckelman'

"""
hasher bindings

ctypes bindings for libhasher
"""

from ctypes import *

import sys
import logging

logger = logging.getLogger(__name__)

lib_base = 'libhasher'

exts = {'win32': '.dll', 'darwin': '.dylib'}

lib_name = lib_base + exts.get(sys.platform, '.so')

try:
    _hasher = CDLL(lib_name)
except Exception as e:
    logger.critical("Could not load {} from {}".format(lib_name, sys.path))
    raise e


class HasherHashes(Structure):
    _fields_ = [
        ('md5', c_uint8 * 16),
        ('sha1', c_uint8 * 20),
        ('sha2_224', c_uint8 * 28),
        ('sha2_256', c_uint8 * 32),
        ('sha2_384', c_uint8 * 48),
        ('sha2_512', c_uint8 * 64),
        ('sha3_224', c_uint8 * 28),
        ('sha3_256', c_uint8 * 32),
        ('sha3_384', c_uint8 * 48),
        ('sha3_512', c_uint8 * 64),
        ('_fuzzy', c_uint8 * 148),
        ('quick_md5', c_uint8 * 16),
        ('entropy', c_double)
    ]

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.md5[:] == other.md5[:] and
                    self.sha1[:] == other.sha1[:] and
                    self.sha2_224[:] == other.sha2_224[:] and
                    self.sha2_256[:] == other.sha2_256[:] and
                    self.sha2_384[:] == other.sha2_384[:] and
                    self.sha2_512[:] == other.sha2_512[:] and
                    self.sha3_224[:] == other.sha3_224[:] and
                    self.sha3_256[:] == other.sha3_256[:] and
                    self.sha3_384[:] == other.sha3_384[:] and
                    self.sha3_512[:] == other.sha3_512[:] and
                    self.fuzzy == other.fuzzy and
                    self.entropy == other.entropy and
                    self.quick_md5[:] == other.quick_md5[:])
        return NotImplemented

    @property
    def fuzzy(self):
        return bytes(self._fuzzy).rstrip(b'\x00').decode('ascii')


class HasherError(Structure):
    _fields_ = [('message', c_char_p)]


# const char* sfhash_hash_name(SFHASH_HashAlgorithm hash_type);
_sfhash_hash_name = _hasher.sfhash_create_hasher
_sfhash_hash_name.argtypes = [c_uint32]
_sfhash_hash_name.restype = c_char_p

# uint32_t sfhash_hash_length(SFHASH_HashAlgorithm hash_type);
_sfhash_hash_length = _hasher.sfhash_hash_length
_sfhash_hash_length.argtypes = [c_uint32]
_sfhash_hash_length.restype = c_uint32

# void sfhash_free_error(SFHASH_Error* err);
_sfhash_free_error = _hasher.sfhash_free_error
_sfhash_free_error.argtypes = [c_void_p]
_sfhash_free_error.restype = None

# SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs)
_sfhash_create_hasher = _hasher.sfhash_create_hasher
_sfhash_create_hasher.argtypes = [c_uint32]
_sfhash_create_hasher.restype = c_void_p

# SFHASH_Hasher* sfhash_clone_hasher(const SFHASH_Hasher* hasher);
_sfhash_clone_hasher = _hasher.sfhash_clone_hasher
_sfhash_clone_hasher.argtypes = [c_void_p]
_sfhash_clone_hasher.restype = c_void_p

# void sfhash_update_hasher(SFHASH_Hasher* hasher, const void* beg, const void* end);
_sfhash_update_hasher = _hasher.sfhash_update_hasher
_sfhash_update_hasher.argtypes = [c_void_p, c_void_p, c_void_p]
_sfhash_update_hasher.restype = None

# void sfhash_hasher_set_total_input_length(SFHASH_Hasher* hasher, uint64_t total_fixed_length);
_sfhash_hasher_set_total_input_length = _hasher.sfhash_hasher_set_total_input_length
_sfhash_hasher_set_total_input_length.argtypes = [c_void_p, c_uint64]
_sfhash_hasher_set_total_input_length.restype = None

# void sfhash_get_hashes(SFHASH_Hasher* hasher, SFHASH_HashValues* out_hashes);
_sfhash_get_hashes = _hasher.sfhash_get_hashes
_sfhash_get_hashes.argtypes = [c_void_p, POINTER(HasherHashes)]
_sfhash_get_hashes.restype = None

# void sfhash_reset_hasher(SFHASH_Hasher* hasher);
_sfhash_reset_hasher = _hasher.sfhash_reset_hasher
_sfhash_reset_hasher.argtypes = [c_void_p]
_sfhash_reset_hasher.restype = None

# void sfhash_destroy_hasher(SFHASH_Hasher* hasher);
_sfhash_destroy_hasher = _hasher.sfhash_destroy_hasher
_sfhash_destroy_hasher.argtypes = [c_void_p]
_sfhash_destroy_hasher.restype = None

# SFHASH_HashSetInfo* sfhash_load_hashset_info(const void* beg, const void* end, SFHASH_Error** err);
_sfhash_load_hashset_info = _hasher.sfhash_load_hashset_info
_sfhash_load_hashset_info.argtypes = [c_void_p, c_void_p, POINTER(POINTER(HasherError))]
_sfhash_load_hashset_info.restype = c_void_p

# void sfhash_destroy_hashset_info(SFHASH_HashSetInfo* hsinfo);
_sfhash_destroy_hashset_info = _hasher.sfhash_destroy_hashset_info
_sfhash_destroy_hashset_info.argtypes = [c_void_p]
_sfhash_destroy_hashset_info.restype = None

# SFHASH_HashSet* sfhash_load_hashset(const SFHASH_HashSetInfo* hsinfo, const void* beg, const void* end, bool shared, SFHASH_Error** err);
_sfhash_load_hashset = _hasher.sfhash_load_hashset
_sfhash_load_hashset.argtypes = [c_void_p, c_void_p, c_void_p, c_bool, POINTER(POINTER(HasherError))]
_sfhash_load_hashset.restype = c_void_p

# void sfhash_destroy_hashset(SFHASH_HashSet* hset)
_sfhash_destroy_hashset = _hasher.sfhash_destroy_hashset
_sfhash_destroy_hashset.argtypes = [c_void_p]
_sfhash_destroy_hashset.restype = None

# bool sfhash_lookup_hashset(const SFHASH_HashSet* hset, const void* hash);
_sfhash_lookup_hashset = _hasher.sfhash_lookup_hashset
_sfhash_lookup_hashset.argtypes = [c_void_p, c_void_p]
_sfhash_lookup_hashset.restype = c_bool

# SFHASH_SizeSet* sfhash_load_sizeset(SFHASH_HashSetInfo* hsinfo, const void* beg, const void* end, SFHASH_Error** err);
_sfhash_load_sizeset = _hasher.sfhash_load_sizeset
_sfhash_load_sizeset.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(POINTER(HasherError))]
_sfhash_load_sizeset.restype = c_void_p

# void sfhash_destroy_sizeset(SFHASH_SizeSet* sset);
_sfhash_destroy_sizeset = _hasher.sfhash_destroy_sizeset
_sfhash_destroy_sizeset.argtypes = [c_void_p]
_sfhash_destroy_sizeset.restype = None

# bool sfhash_lookup_sizeset(const SFHASH_SizeSet* sset, uint64_t size);
_sfhash_lookup_sizeset = _hasher.sfhash_lookup_sizeset
_sfhash_lookup_sizeset.argtypes = [c_void_p, c_uint64]
_sfhash_lookup_sizeset.restype = c_bool

# SFHASH_FuzzyMatcher* sfhash_create_fuzzy_matcher(const void* beg, const void* end);
_sfhash_create_fuzzy_matcher = _hasher.sfhash_create_fuzzy_matcher
_sfhash_create_fuzzy_matcher.argtypes = [c_void_p, c_void_p]
_sfhash_create_fuzzy_matcher.restype = c_void_p

# const SFHASH_FuzzyResult* sfhash_fuzzy_matcher_compare(SFHASH_FuzzyMatcher* matcher, const void* beg, const void* end);
_sfhash_fuzzy_matcher_compare = _hasher.sfhash_fuzzy_matcher_compare
_sfhash_fuzzy_matcher_compare.argtypes = [c_void_p, c_void_p, c_void_p]
_sfhash_fuzzy_matcher_compare.restype = c_void_p

# size_t sfhash_fuzzy_result_count(const SFHASH_FuzzyResult* result);
_sfhash_fuzzy_result_count = _hasher.sfhash_fuzzy_result_count
_sfhash_fuzzy_result_count.argtypes = [c_void_p]
_sfhash_fuzzy_result_count.restype = c_size_t

# const char* sfhash_fuzzy_result_filename(const SFHASH_FuzzyResult* result, size_t i);
_sfhash_fuzzy_result_filename = _hasher.sfhash_fuzzy_result_filename
_sfhash_fuzzy_result_filename.argtypes = [c_void_p, c_size_t]
_sfhash_fuzzy_result_filename.restype = c_char_p

# const char* sfhash_fuzzy_result_query_filename(const SFHASH_FuzzyResult* result);
_sfhash_fuzzy_result_query_filename = _hasher.sfhash_fuzzy_result_query_filename
_sfhash_fuzzy_result_query_filename.argtypes = [c_void_p]
_sfhash_fuzzy_result_query_filename.restype = c_char_p

# int sfhash_fuzzy_result_score(const SFHASH_FuzzyResult* result, size_t i);
_sfhash_fuzzy_result_score = _hasher.sfhash_fuzzy_result_score
_sfhash_fuzzy_result_score.argtypes = [c_void_p, c_size_t]
_sfhash_fuzzy_result_score.restype = c_int

# void sfhash_destroy_fuzzy_match(const SFHASH_FuzzyResult* result);
_sfhash_destroy_fuzzy_match = _hasher.sfhash_destroy_fuzzy_match
_sfhash_destroy_fuzzy_match.argtypes = [c_void_p]
_sfhash_destroy_fuzzy_match.restype = None

# void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);
_sfhash_destroy_fuzzy_matcher = _hasher.sfhash_destroy_fuzzy_matcher
_sfhash_destroy_fuzzy_matcher.argtypes = [c_void_p]
_sfhash_destroy_fuzzy_matcher.restype = None

# SFHASH_FileMatcher* sfhash_create_matcher(const void* beg, const void* end, SFHASH_Error** err);
_sfhash_create_matcher = _hasher.sfhash_create_matcher
_sfhash_create_matcher.argtypes = [c_void_p, c_void_p, POINTER(POINTER(HasherError))]
_sfhash_create_matcher.restype = c_void_p

# int sfhash_matcher_has_size(const SFHASH_FileMatcher* matcher, uint64_t size);
_sfhash_matcher_has_size = _hasher.sfhash_matcher_has_size
_sfhash_matcher_has_size.argtypes = [c_void_p, c_uint64]
_sfhash_matcher_has_size.restype = c_bool

# int sfhash_matcher_has_hash(const SFHASH_FileMatcher* matcher, const uint8_t* sha1);
_sfhash_matcher_has_hash = _hasher.sfhash_matcher_has_hash
_sfhash_matcher_has_hash.argtypes = [c_void_p, POINTER(c_uint8)]
_sfhash_matcher_has_hash.restype = c_bool

# int sfhash_matcher_has_filename(const SFHASH_FileMatcher* matcher, const char* filename);
_sfhash_matcher_has_filename = _hasher.sfhash_matcher_has_filename
_sfhash_matcher_has_filename.argtypes = [c_void_p, c_char_p]
_sfhash_matcher_has_filename.restype = c_bool

# void sfhash_destroy_matcher(SFHASH_FileMatcher* matcher);
_sfhash_destroy_matcher = _hasher.sfhash_destroy_matcher
_sfhash_destroy_matcher.argtypes = [c_void_p]
_sfhash_destroy_matcher.restype = None


MD5       = 1 <<  0
SHA1      = 1 <<  1
SHA2_224  = 1 <<  2
SHA2_256  = 1 <<  3
SHA2_384  = 1 <<  4
SHA2_512  = 1 <<  5
SHA3_224  = 1 <<  6
SHA3_256  = 1 <<  7
SHA3_384  = 1 <<  8
SHA3_512  = 1 <<  9
FUZZY     = 1 << 10
ENTROPY   = 1 << 11
QUICK_MD5 = 1 << 12
OTHER     = 1 << 31


c_ssize_p = POINTER(c_ssize_t)


class Py_buffer(Structure):
    _fields_ = [
        ('buf', c_void_p),
        ('obj', py_object),
        ('len', c_ssize_t),
        ('itemsize', c_ssize_t),
        ('readonly', c_int),
        ('ndim', c_int),
        ('format', c_char_p),
        ('shape', c_ssize_p),
        ('strides', c_ssize_p),
        ('suboffsets', c_ssize_p),
        ('internal', c_void_p)
    ]


def ptr_range(buf, pbuf, ptype):
    blen = len(buf)

    if isinstance(buf, bytes):
        # yay, we can get a pointer from a bytes
        beg = cast(buf, POINTER(ptype * 1))[0]
    elif blen >= 8 and (not isinstance(buf, memoryview) or not buf.readonly):
        # we have a writable buffer; from_buffer requires len >= 8
        beg = (ptype * 1).from_buffer(buf)
    else:
        # we have a read-only memoryview, so have to do some gymnastics
        obj = py_object(buf)
        try:
            pythonapi.PyObject_GetBuffer(obj, byref(pbuf), 0)
            beg = (ptype * pbuf.len).from_address(pbuf.buf)
        finally:
            pythonapi.PyBuffer_Release(byref(pbuf))

    end = cast(beg, POINTER(ptype * 1))[blen]
    return beg, end


class Handle(object):
    def __init__(self, handle):
        self.handle = handle

    def __bool__(self):
        return bool(self.handle)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def destroy(self):
        self.handle = None

    def throwIfDestroyed(self):
        if not self.handle:
            raise RuntimeError(f"{self.__class__.__name__} handle is destroyed")

    def get(self):
        self.throwIfDestroyed()
        return self.handle


class Error(Handle):
    def __init__(self):
        super().__init__(c_void_p())

    def destroy(self):
        _sfhash_free_error(self.handle)
        super().destroy()

    def get(self):
        return self.handle

    def __str__(self):
        return str(self.handle.message.decode('utf-8')) if self.handle else ''


class Hasher(Handle):
    def __init__(self, algs, clone=None):
        super().__init__(_sfhash_clone_hasher(clone) if clone else _sfhash_create_hasher(algs))
        self.algs = algs
        self.pbuf = Py_buffer()

    def destroy(self):
        _sfhash_destroy_hasher(self.handle)
        super().destroy()

    def clone(self):
        return Hasher(self.algs, clone=self.get())

    def update(self, buf):
        _sfhash_update_hasher(self.get(), *ptr_range(buf, self.pbuf, c_uint8))

    def set_total_input_length(self, length):
        _sfhash_hasher_set_total_input_length(self.get(), length)

    def reset(self):
        _sfhash_reset_hasher(self.get())

    def get_hashes(self):
        h = HasherHashes()
        _sfhash_get_hashes(self.get(), byref(h))
        return h

    def get_hashes_dict(self, rounding=3):
        h = self.get_hashes()
        d = {}

        if self.algs & MD5:
            d['md5'] = bytes(h.md5).hex()
        if self.algs & SHA1:
            d['sha1'] = bytes(h.sha1).hex()
        if self.algs & SHA2_224:
            d['sha2_224'] = bytes(h.sha2_224).hex()
        if self.algs & SHA2_256:
            d['sha2_256'] = bytes(h.sha2_256).hex()
        if self.algs & SHA2_384:
            d['sha2_384'] = bytes(h.sha2_384).hex()
        if self.algs & SHA2_512:
            d['sha2_512'] = bytes(h.sha2_512).hex()
        if self.algs & SHA3_224:
            d['sha3_224'] = bytes(h.sha3_224).hex()
        if self.algs & SHA3_256:
            d['sha3_256'] = bytes(h.sha3_256).hex()
        if self.algs & SHA3_384:
            d['sha3_384'] = bytes(h.sha3_384).hex()
        if self.algs & SHA3_512:
            d['sha3_512'] = bytes(h.sha3_512).hex()
        if self.algs & FUZZY:
            d['fuzzy'] = h.fuzzy
        if self.algs & ENTROPY:
            d['entropy'] = round(h.entropy, rounding) if rounding is not None else h.entropy
        if self.algs & QUICK_MD5:
            d['quick_md5'] = bytes(h.quick_md5).hex()

        return d


class HashSetInfo(Handle):
    def __init__(self, buf):
        with Error() as err:
            super().__init__(_sfhash_load_hashset_info(*ptr_range(buf, Py_buffer(), c_char), byref(err.get())))
            if err:
                raise RuntimeError(err)

    def destroy(self):
        _sfhash_destroy_hashset_info(self.handle)
        super().destroy()

# TODO: member access


class HashSet(Handle):
    def __init__(self, info, buf):
        with Error() as err:
            super().__init__(_sfhash_load_hashset(info.get(), *ptr_range(buf, Py_buffer(), c_char), byref(err.get())))
            if err:
                raise RuntimeError(err)

    def destroy(self):
        _sfhash_destroy_hashset(self.handle)
        super().destroy()

    def lookup(h):
        return _sfhsah_lookup_hashset(self.get(), byref(h))


class SizeSet(Handle):
    def __init__(self, info, buf):
        with Error() as err:
            super().__init__(_sfhash_load_sizeset(info.get(), *ptr_range(buf, Py_buffer(), c_char), byref(err.get())))
            if err:
                raise RuntimeError(err)

    def destroy(self):
        _sfhash_destroy_sizeset(self.handle)
        super().destroy()

    def lookup(size):
        return _sfhsah_lookup_sizeset(self.get(), size)


class FuzzyResult(Handle):
    def __init__(self, ptr):
        super().__init__(ptr)

    @property
    def query_filename(self):
        return _sfhash_fuzzy_result_query_filename(self.get()).decode('utf-8')

    @property
    def count(self):
        return _sfhash_fuzzy_result_count(self.get())

    def filename(self, i):
        return _sfhash_fuzzy_result_filename(self.get(), i).decode('utf-8')

    def score(self, i):
        return _sfhash_fuzzy_result_score(self.get(), i)

    def destroy(self):
        _sfhash_destroy_fuzzy_match(self.handle)
        super().destroy()


class FuzzyMatcher(Handle):
    def __init__(self, buf):
        self.pbuf = Py_buffer()
        self.matcher_buf = buf.encode('utf-8')
        super().__init__(_sfhash_create_fuzzy_matcher(*ptr_range(self.matcher_buf, self.pbuf, c_char)))
        if not self.handle:
            raise Exception("Invalid hashes file")

    def destroy(self):
        _sfhash_destroy_fuzzy_matcher(self.get())
        super().destroy()

    def matches(self, sig):
        sig_bytes = sig.encode('utf-8')
        with FuzzyResult(_sfhash_fuzzy_matcher_compare(self.get(), *ptr_range(sig_bytes, self.pbuf, c_char))) as result:
            for i in range(result.count):
                yield (result.filename(i), result.query_filename, result.score(i))


class Matcher(Handle):
    def __init__(self, buf):
        with Error() as err:
            super().__init__(_sfhash_create_matcher(*ptr_range(buf, Py_buffer(), c_char), byref(err.get())))
            if err:
                raise RuntimeError(err)

    def destroy(self):
        _sfhash_destroy_matcher(self.handle)
        super().destroy()

    def has_size(size):
        return _sfhash_matcher_has_size(self.get(), size)

    def has_hash(h):
        return _sfhash_matcher_has_hash(self.get(), byref(h))

    def has_filename(filename):
        return _sfhash_matcher_has_filename(self.get(), filename.encode('utf-8'))
