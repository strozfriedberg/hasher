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
lib_name = lib_base + ('.dll' if sys.platform == 'win32' else '.so')

try:
    _hasher = CDLL(lib_name)
except Exception as e:
    logger.critical("Could not load {} from {}".format(lib_name, sys.path))
    raise e


class HasherHashes(Structure):
    _fields_ = [('md5', c_uint8 * 16),
                ('sha1', c_uint8 * 20),
                ('sha256', c_uint8 * 32),
                ('_fuzzy', c_uint8 * 148),
                ('entropy', c_double)]

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.md5[:] == other.md5[:] and
                    self.sha1[:] == other.sha1[:] and
                    self.sha256[:] == other.sha256[:] and
                    self.fuzzy == other.fuzzy and
                    self.entropy == other.entropy)
        return NotImplemented

    @property
    def fuzzy(self):
      return bytes(self._fuzzy).rstrip(b'\x00').decode('ascii')


# SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs);
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

# SFHASH_FuzzyMatcher* sfhash_create_fuzzy_matcher(const char* beg, const char* end);
_sfhash_create_fuzzy_matcher = _hasher.sfhash_create_fuzzy_matcher
_sfhash_create_fuzzy_matcher.argtypes = [c_void_p, c_void_p]
_sfhash_create_fuzzy_matcher.restype = c_void_p

# int sfhash_fuzzy_matcher_compare(SFHASH_FuzzyMatcher* matcher, const char* beg, const char* end);
_sfhash_fuzzy_matcher_compare = _hasher.sfhash_fuzzy_matcher_compare
_sfhash_fuzzy_matcher_compare.argtypes = [c_void_p, c_void_p, c_void_p]
_sfhash_fuzzy_matcher_compare.restype = c_int

# SFHASH_FuzzyResult* sfhash_fuzzy_get_match(SFHASH_FuzzyMatcher* matcher, int i);
_sfhash_fuzzy_get_match = _hasher.sfhash_fuzzy_get_match
_sfhash_fuzzy_get_match.argtypes = [c_void_p, c_int]
_sfhash_fuzzy_get_match.restype = c_void_p

# const char* sfhash_fuzzy_result_filename(const SFHASH_FuzzyResult* result);
_sfhash_fuzzy_result_filename = _hasher.sfhash_fuzzy_result_filename
_sfhash_fuzzy_result_filename.argtypes = [c_void_p]
_sfhash_fuzzy_result_filename.restype = c_char_p

# const char* sfhash_fuzzy_result_query_filename(const SFHASH_FuzzyResult* result);
_sfhash_fuzzy_result_query_filename = _hasher.sfhash_fuzzy_result_query_filename
_sfhash_fuzzy_result_query_filename.argtypes = [c_void_p]
_sfhash_fuzzy_result_query_filename.restype = c_char_p

# int sfhash_fuzzy_result_score(const SFHASH_FuzzyResult* result);
_sfhash_fuzzy_result_score = _hasher.sfhash_fuzzy_result_score
_sfhash_fuzzy_result_score.argtypes = [c_void_p]
_sfhash_fuzzy_result_score.restype = c_int

# void sfhash_fuzzy_destroy_match(SFHASH_FuzzyResult* result);
_sfhash_fuzzy_destroy_match = _hasher.sfhash_fuzzy_destroy_match
_sfhash_fuzzy_destroy_match.argtypes = [c_void_p]
_sfhash_fuzzy_destroy_match.restype = None

# void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);
_sfhash_destroy_fuzzy_matcher = _hasher.sfhash_destroy_fuzzy_matcher
_sfhash_fuzzy_destroy_fuzzy_matcher.argtypes = [c_void_p]
_sfhash_fuzzy_destroy_fuzzy_matcher.restype = None


MD5     = 1 << 0
SHA1    = 1 << 1
SHA256  = 1 << 2
FUZZY   = 1 << 3
ENTROPY = 1 << 4


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
        beg = cast(buf, POINTER(ptype * blen))[0]
    elif blen >= 8 and (not isinstance(buf, memoryview) or not buf.readonly):
        # we have a writable buffer; from_buffer requires len >= 8
        beg = (ptype * blen).from_buffer(buf)
    else:
        # we have a read-only memoryview, so have to do some gymnastics
        obj = py_object(buf)
        try:
            pythonapi.PyObject_GetBuffer(obj, byref(pbuf), 0)
            beg = (ptype * pbuf.len).from_address(pbuf.buf)
        finally:
            pythonapi.PyBuffer_Release(byref(pbuf))

    end = byref(beg, blen)
    return beg, end


class Hasher(object):
    def __init__(self, algs, clone=None):
        self.hasher = _sfhash_clone_hasher(clone) if clone else _sfhash_create_hasher(algs)
        self.pbuf = Py_buffer()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def destroy(self):
        _sfhash_destroy_hasher(self.hasher)
        self.hasher = None

    def clone(self):
        return Hasher(0, clone=self.hasher)

    def update(self, buf):
        _sfhash_update_hasher(self.hasher, *ptr_range(buf, self.pbuf, c_uint8))

    def set_total_input_length(self, length):
        _sfhash_hasher_set_total_input_length(self.hasher, length)

    def reset(self):
        _sfhash_reset_hasher(self.hasher)

    def get_hashes(self):
        h = HasherHashes()
        _sfhash_get_hashes(self.hasher, byref(h))
        return h

class FuzzyResult(object):
    def __init__(self, ptr):
        self.ptr = ptr

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    @property
    def filename(self):
        return _sfhash_fuzzy_result_filename(self.ptr).decode('utf-8')

    @property
    def query_filename(self):
        return _sfhash_fuzzy_result_query_filename(self.ptr).decode('utf-8')

    @property
    def score(self):
        return _sfhash_fuzzy_result_score(self.ptr)

    def destroy(self):
        _sfhash_fuzzy_destroy_match(self.ptr)


class FuzzyMatcher(object):
    def __init__(self, buf):
        self.pbuf = Py_buffer()
        self.matcher_buf = buf.encode('utf-8')
        self.ptr = _sfhash_create_fuzzy_matcher(*ptr_range(self.matcher_buf, self.pbuf, c_char))
        if not self.ptr:
            raise Exception("Invalid hashes file")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def destroy(self):
        _sfhash_destroy_fuzzy_matcher(self.ptr)

    def matches(self, sig):
        sig_bytes = sig.encode('utf-8')
        matches = _sfhash_fuzzy_matcher_compare(self.ptr, *ptr_range(sig_bytes, self.pbuf, c_char))
        for x in range(matches):
            with FuzzyResult(_sfhash_fuzzy_get_match(self.ptr, x)) as result:
                yield (result.filename, result.query_filename, result.score)
