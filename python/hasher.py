__author__ = 'juckelman'

"""
hasher bindings

ctypes bindings for libhasher
"""

from ctypes import *

import os
from pathlib import Path
import sys
import logging

logger = logging.getLogger(__name__)

lib_base = 'libhasher'

exts = {'win32': '.dll', 'darwin': '.dylib'}

lib_name = lib_base + exts.get(sys.platform, '.so')

if sys.platform == 'win32':
    os.add_dll_directory(Path(__file__).parent.parent / Path("win64"))

try:
    _hasher = CDLL(lib_name)
except Exception as e:
    logger.critical("Could not load {} from {}".format(lib_name, sys.path))
    raise e


#
# mappings and enums
#

# the complete list of hash names/enums
ALL_HASHES = [
    ('md5',       1 <<  0),
    ('sha1',      1 <<  1),
    ('sha2_224',  1 <<  2),
    ('sha2_256',  1 <<  3),
    ('sha2_384',  1 <<  4),
    ('sha2_512',  1 <<  5),
    ('sha3_224',  1 <<  6),
    ('sha3_256',  1 <<  7),
    ('sha3_384',  1 <<  8),
    ('sha3_512',  1 <<  9),
    ('blake3',    1 << 10),
    ('fuzzy',     1 << 11),
    ('entropy',   1 << 12),
    ('size',      1 << 13),
    ('quick_md5', 1 << 14)
]

# the list of hash names/enums for hashes which are hexadecimal
HEX_HASHES = [(n, a) for n, a in ALL_HASHES if n not in ('entropy', 'fuzzy')]

# map hash names to enums
HASH_NAME_TO_ENUM = { name: mask for name, mask in ALL_HASHES }

# map hash enums to names
ENUM_TO_MEMBER_NAME = { mask: name for name, mask in ALL_HASHES }

# set the module-level algorithm enums; this produces constants
# with the same names and values as the enum in the C API; would
# there were a way to read enum names using ctypes...
this_module = sys.modules[__name__]

for name, mask in ALL_HASHES:
    setattr(this_module, name.upper(), mask)


#
# structs
#

class HasherHashes(Structure):
    _fields_ = [
        ('md5',       c_uint8 * 16),
        ('sha1',      c_uint8 * 20),
        ('sha2_224',  c_uint8 * 28),
        ('sha2_256',  c_uint8 * 32),
        ('sha2_384',  c_uint8 * 48),
        ('sha2_512',  c_uint8 * 64),
        ('sha3_224',  c_uint8 * 28),
        ('sha3_256',  c_uint8 * 32),
        ('sha3_384',  c_uint8 * 48),
        ('sha3_512',  c_uint8 * 64),
        ('blake3',    c_uint8 * 32),
        ('fuzzy',     c_uint8 * 148),
        ('quick_md5', c_uint8 * 16),
        ('entropy',   c_double)
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
                    self.blake3[:] == other.blake3[:] and
                    self.fuzzy[:] == other.fuzzy[:] and
                    self.entropy == other.entropy and
                    self.quick_md5[:] == other.quick_md5[:])
        return NotImplemented

    def hash_for_alg(self, alg):
        return getattr(self, ENUM_TO_MEMBER_NAME[alg])

    def to_dict(self, algs, rounding=3):
        d = {
            name: bytes(getattr(self, name)).hex()
            for name, alg in HEX_HASHES if alg & algs
        }

        if algs & ENTROPY:
            d['entropy'] = round(self.entropy, rounding) if rounding is not None else self.entropy

        if algs & FUZZY:
            d['fuzzy'] = bytes(self.fuzzy).rstrip(b'\x00').decode('ascii')

        return d

    @classmethod
    def from_dict(cls, d):
        h = cls()

        for k, v in d.items():
            if k == 'entropy':
                h.entropy = v
            elif k == 'fuzzy':
                h.fuzzy = (c_ubyte * sizeof(h.fuzzy))(*v.encode('ascii'))
            else:
                setattr(h, k, (c_ubyte * sizeof(getattr(h, k)))(*bytes.fromhex(v)))

        return h


class HasherError(Structure):
    _fields_ = [('message', c_char_p)]


# const char* sfhash_hash_name(SFHASH_HashAlgorithm hash_type);
_sfhash_hash_name = _hasher.sfhash_hash_name
_sfhash_hash_name.argtypes = [c_uint32]
_sfhash_hash_name.restype = c_char_p

# const char* sfhash_hash_type(const char* name);
_sfhash_hash_type = _hasher.sfhash_hash_type
_sfhash_hash_type.argtypes = [c_char_p]
_sfhash_hash_type.restype = c_uint32

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

# SFHASH_HashSet* sfhash_load_hashset(const void* beg, const void* end, SFHASH_Error** err);
_sfhash_load_hashset = _hasher.sfhash_load_hashset
_sfhash_load_hashset.argtypes = [c_void_p, c_void_p, POINTER(POINTER(HasherError))]
_sfhash_load_hashset.restype = c_void_p

# void sfhash_destroy_hashset(SFHASH_HashSet* hset);
_sfhash_destroy_hashset = _hasher.sfhash_destroy_hashset
_sfhash_destroy_hashset.argtypes = [c_void_p]
_sfhash_destroy_hashset.restype = None

# const char* sfhash_hashset_name(const SFHASH_Hashset* hset);
_sfhash_hashset_name = _hasher.sfhash_hashset_name
_sfhash_hashset_name.argtypes = [c_void_p]
_sfhash_hashset_name.restype = c_char_p

# const char* sfhash_hashset_description(const SFHASH_Hashset* hset);
_sfhash_hashset_description = _hasher.sfhash_hashset_description
_sfhash_hashset_description.argtypes = [c_void_p]
_sfhash_hashset_description.restype = c_char_p

# const char* sfhash_hashset_timestamp(const SFHASH_Hashset* hset);
_sfhash_hashset_timestamp = _hasher.sfhash_hashset_timestamp
_sfhash_hashset_timestamp.argtypes = [c_void_p]
_sfhash_hashset_timestamp.restype = c_char_p

# const char* sfhash_hashset_sha2_256(const SFHASH_Hashset* hset);
_sfhash_hashset_sha2_256 = _hasher.sfhash_hashset_sha2_256
_sfhash_hashset_sha2_256.argtypes = [c_void_p]
_sfhash_hashset_sha2_256.restype = c_void_p

# size_t sfhash_hashset_count(const SFHASH_Hashset* hset, size_t tidx);
_sfhash_hashset_count = _hasher.sfhash_hashset_count
_sfhash_hashset_count.argtypes = [c_void_p, c_size_t]
_sfhash_hashset_count.restype = c_size_t

# int sfhash_hashset_index_for_type(const SFHASH_Hashset* hset, SFHASH_HashAlgorithm htype);
_sfhash_hashset_index_for_type = _hasher.sfhash_hashset_index_for_type
_sfhash_hashset_index_for_type.argtypes = [c_void_p, c_uint32]
_sfhash_hashset_index_for_type.restype = c_int

# bool sfhash_hashset_lookup(const SFHASH_Hashset* hset, size_t tidx, const void* hash);
_sfhash_hashset_lookup = _hasher.sfhash_hashset_lookup
_sfhash_hashset_lookup.argtypes = [c_void_p, c_size_t, c_void_p]
_sfhash_hashset_lookup.restype = c_bool

# SFHASH_FuzzyMatcher* sfhash_create_fuzzy_matcher(const void* beg, const void* end);
_sfhash_create_fuzzy_matcher = _hasher.sfhash_create_fuzzy_matcher
_sfhash_create_fuzzy_matcher.argtypes = [c_void_p, c_void_p]
_sfhash_create_fuzzy_matcher.restype = c_void_p

# SFHASH_FuzzyResult* sfhash_fuzzy_matcher_compare(SFHASH_FuzzyMatcher* matcher, const void* beg, const void* end);
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

# void sfhash_destroy_fuzzy_match(SFHASH_FuzzyResult* result);
_sfhash_destroy_fuzzy_match = _hasher.sfhash_destroy_fuzzy_match
_sfhash_destroy_fuzzy_match.argtypes = [c_void_p]
_sfhash_destroy_fuzzy_match.restype = None

# void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);
_sfhash_destroy_fuzzy_matcher = _hasher.sfhash_destroy_fuzzy_matcher
_sfhash_destroy_fuzzy_matcher.argtypes = [c_void_p]
_sfhash_destroy_fuzzy_matcher.restype = None

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


def buf_beg(buf, ptype):
    # Of note for retrieving pointers to buffers:
    #
    # "T * 1" produces the ctypes type corresponding to the C type T[1].
    # The buffer which we cast using this is unlikely to be of length 1,
    # but this doesn't matter because C has type punning and all we really
    # want is a pointer to the first element (= a pointer to the buffer)
    # anyway.
    #
    # Py_buffer is a struct defined in Python's C API for use with objects
    # implementing the buffer protocol. Q.v.:
    #
    # https://docs.python.org/3/c-api/buffer.html#c.Py_buffer
    #
    # (ptype * 1).from_buffer(buf) is a fast, simple way to get a pointer
    # from writable buffers, but unfortunately it throws on very short
    # (< 8 bytes) or readonly buffers which makes the total time for these
    # much worse than had we not tried it at all.
    #
    obj = py_object(buf)
    pybuf = Py_buffer()
    try:
        pythonapi.PyObject_GetBuffer(obj, byref(pybuf), 0)
        return (ptype * 1).from_address(pybuf.buf)
    finally:
        pythonapi.PyBuffer_Release(byref(pybuf))


def buf_range(buf, ptype):
    beg = buf_beg(buf, ptype)
    end = cast(beg, POINTER(ptype * 1))[len(buf)]
    return beg, end


def buf_end(buf, ptype):
    return buf_range(buf, ptype)[1]


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
        super().__init__(POINTER(HasherError)())

    def destroy(self):
        _sfhash_free_error(self.handle)
        super().destroy()

    def get(self):
        return self.handle

    def __str__(self):
        return self.handle.contents.message.decode('utf-8') if self.handle else ''


def hash_name(alg):
    return _sfhash_hash_name(alg).decode('utf-8')


def hash_alg(name):
    return _sfhash_hash_type(name.encode('utf-8')) or None


class Hasher(Handle):
    def __init__(self, algs, clone=None):
        super().__init__(_sfhash_clone_hasher(clone) if clone else _sfhash_create_hasher(algs))
        self.algs = algs

    def destroy(self):
        _sfhash_destroy_hasher(self.handle)
        super().destroy()

    def clone(self):
        return Hasher(self.algs, clone=self.get())

    def update(self, buf):
        _sfhash_update_hasher(self.get(), *buf_range(buf, c_uint8))

    def set_total_input_length(self, length):
        _sfhash_hasher_set_total_input_length(self.get(), length)

    def reset(self):
        _sfhash_reset_hasher(self.get())

    def get_hashes(self):
        h = HasherHashes()
        _sfhash_get_hashes(self.get(), byref(h))
        return h


class Hashset(object):
    def __init__(self, hset, idx):
        self.hset = hset
        self.idx = idx

    def __contains__(self, h):
        return _sfhash_hashset_lookup(self.hset, self.idx, buf_beg(h, c_uint8))

    def count(self):
        return _sfhash_hashset_count(self.hset, self.idx)


class HSet(Handle):
    # For internal use only. Use load() to load a hashset.
    def __init__(self, buf):
        super().__init__(buf)

    def destroy(self):
        _sfhash_destroy_hashset(self.handle)
        super().destroy()

    def name(self):
        return _sfhash_hashset_name(self.get()).decode('utf-8')

    def description(self):
        return _sfhash_hashset_description(self.get()).decode('utf-8')

    def timestamp(self):
        return _sfhash_hashset_timestamp(self.get()).decode('utf-8')

    def sha2_256(self):
        return _sfhash_hashset_sha2_256(self.get())

    def index(self, ht):
        return _sfhash_hashset_index_for_type(self.get(), ht)

    def hashset(self, ht):
        return Hashset(self.get(), self.index(ht))

    @classmethod
    def load(cls, buf):
        with Error() as err:
            hset = cls(_sfhash_load_hashset(*buf_range(buf, c_char), byref(err.get())))
            if err:
                raise RuntimeError(str(err))
        return hset


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
        self.matcher_buf = buf.encode('utf-8')
        super().__init__(_sfhash_create_fuzzy_matcher(*buf_range(self.matcher_buf, c_char)))
        if not self.handle:
            raise Exception("Invalid hashes file")

    def destroy(self):
        _sfhash_destroy_fuzzy_matcher(self.get())
        super().destroy()

    def matches(self, sig):
        sig_bytes = sig.encode('utf-8')
        with FuzzyResult(_sfhash_fuzzy_matcher_compare(self.get(), *buf_range(sig_bytes, c_char))) as result:
            for i in range(result.count):
                yield (result.filename(i), result.query_filename, result.score(i))
