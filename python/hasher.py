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
    ('quick_md5', 1 << 13),
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

OTHER = 1 << 31


#
# structs
#

class HashSetInfoStruct(Structure):
    _fields_ = [
        ('version',        c_uint64),
        ('hash_type',      c_uint32),
        ('hash_length',    c_uint64),
        ('flags',          c_uint64),
        ('hashset_size',   c_uint64),
        ('hashset_off',    c_uint64),
        ('sizes_off',      c_uint64),
        ('radius',         c_uint64),
        ('hashset_sha256', c_uint8 * 32),
        ('hashset_name',   c_char_p),
        ('hashset_time',   c_char_p),
        ('hashset_desc',   c_char_p)
    ]


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
_sfhash_load_hashset_info.restype = POINTER(HashSetInfoStruct)

# void sfhash_destroy_hashset_info(SFHASH_HashSetInfo* hsinfo);
_sfhash_destroy_hashset_info = _hasher.sfhash_destroy_hashset_info
_sfhash_destroy_hashset_info.argtypes = [c_void_p]
_sfhash_destroy_hashset_info.restype = None

# SFHASH_HashSetData* sfhash_load_hashset_data(const SFHASH_HashSetInfo* hsinfo, const void* beg, const void* end, SFHASH_Error** err);
_sfhash_load_hashset_data = _hasher.sfhash_load_hashset_data
_sfhash_load_hashset_data.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(POINTER(HasherError))]
_sfhash_load_hashset_data.restype = c_void_p

# void sfhash_destroy_hashset_data(SFHASH_HashSetData* hset)
_sfhash_destroy_hashset_data = _hasher.sfhash_destroy_hashset_data
_sfhash_destroy_hashset_data.argtypes = [c_void_p]
_sfhash_destroy_hashset_data.restype = None

# bool sfhash_lookup_hashset_data(const SFHASH_HashSetData* hset, const void* hash);
_sfhash_lookup_hashset_data = _hasher.sfhash_lookup_hashset_data
_sfhash_lookup_hashset_data.argtypes = [c_void_p, c_void_p]
_sfhash_lookup_hashset_data.restype = c_bool

# SFHASH_HashSet* sfhash_load_hashset(const void* beg, const void* end, SFHASH_Error** err);
_sfhash_load_hashset = _hasher.sfhash_load_hashset
_sfhash_load_hashset.argtypes = [c_void_p, c_void_p, POINTER(POINTER(HasherError))]
_sfhash_load_hashset.restype = c_void_p

# const SFHASH_HashSetInfo* sfhash_info_for_hashset(const SFHASH_HashSet* hset);
_sfhash_info_for_hashset = _hasher.sfhash_info_for_hashset
_sfhash_info_for_hashset.argtypes = [c_void_p]
_sfhash_info_for_hashset.restype = POINTER(HashSetInfoStruct)

# bool sfhash_lookup_hashset(const SFHASH_HashSet* hset, const void* hash);
_sfhash_lookup_hashset = _hasher.sfhash_lookup_hashset
_sfhash_lookup_hashset.argtypes = [c_void_p, c_void_p]
_sfhash_lookup_hashset.restype = c_bool

# void sfhash_destroy_hashset(SFHASH_HashSet* hset);
_sfhash_destroy_hashset = _hasher.sfhash_destroy_hashset
_sfhash_destroy_hashset.argtypes = [c_void_p]
_sfhash_destroy_hashset.restype = None

# SFHASH_HashSet* sfhash_union_hashsets(const SFHASH_HashSet* a, const SFHASH_HashSet* b, void* out, const char* out_name, const char* out_desc);
_sfhash_union_hashsets = _hasher.sfhash_union_hashsets
_sfhash_union_hashsets.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p, POINTER(POINTER(HasherError))]
_sfhash_union_hashsets.restype = c_void_p

# SFHASH_HashSet* sfhash_intersect_hashsets(const SFHASH_HashSet* a, const SFHASH_HashSet* b, void* out, const char* out_name, const char* out_desc);
_sfhash_intersect_hashsets = _hasher.sfhash_intersect_hashsets
_sfhash_intersect_hashsets.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p, POINTER(POINTER(HasherError))]
_sfhash_intersect_hashsets.restype = c_void_p

# SFHASH_HashSet* sfhash_difference_hashsets(const SFHASH_HashSet* a, const SFHASH_HashSet* b, void* out, const char* out_name, const char* out_desc);
_sfhash_difference_hashsets = _hasher.sfhash_difference_hashsets
_sfhash_difference_hashsets.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p, POINTER(POINTER(HasherError))]
_sfhash_difference_hashsets.restype = c_void_p

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
    return HASH_NAME_TO_ENUM.get(name.lower(), None)


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


class HashSetInfo(Handle):
    def __init__(self, buf):
        with Error() as err:
            super().__init__(_sfhash_load_hashset_info(*buf_range(buf, c_char), byref(err.get())))
            if err:
                raise RuntimeError(str(err))

    def destroy(self):
        _sfhash_destroy_hashset_info(self.handle)
        super().destroy()


#
# Reflect the fields of the C struct into our handle; yes, this is better
# than listing them all out.
#
def make_pgetter(s):
    return lambda self: getattr(self.get().contents, s)


for f in HashSetInfoStruct._fields_:
    setattr(HashSetInfo, f[0], property(make_pgetter(f[0])))


class HashSetData(Handle):
    def __init__(self, info, buf):
        # isolate the hashes in the buffer
        hbeg = info.hashset_off
        hend = hbeg + info.hashset_size * info.hash_length
        hdata = memoryview(buf)[hbeg:hend]

        with Error() as err:
            super().__init__(_sfhash_load_hashset_data(info.get(), *buf_range(hdata, c_char), byref(err.get())))
            if err:
                raise RuntimeError(str(err))

    def destroy(self):
        _sfhash_destroy_hashset_data(self.handle)
        super().destroy()

    def __contains__(self, h):
        return _sfhash_lookup_hashset_data(self.get(), buf_beg(h, c_uint8))


class HashSet(Handle):
    def __init__(self, buf):
        super().__init__(buf)

    def destroy(self):
        _sfhash_destroy_hashset(self.handle)
        super().destroy()

    def info(self):
        return _sfhash_info_for_hashset(self.get()).contents

    def __contains__(self, h):
        return _sfhash_lookup_hashset(self.get(), buf_beg(h, c_uint8))

    @classmethod
    def load(cls, buf):
        with Error() as err:
            hs = cls(_sfhash_load_hashset(*buf_range(buf, c_char), byref(err.get())))
            if err:
                raise RuntimeError(str(err))
        return hs

    @classmethod
    def union(cls, left, right, obuf, oname, odesc):
        with Error() as err:
            hs = cls(_sfhash_union_hashsets(left.get(), right.get(), buf_beg(obuf, c_uint8), oname.encode('utf-8'), odesc.encode('utf-8'), byref(err.get())))
            if err:
                raise RuntimeError(str(err))
        return hs

    @classmethod
    def intersect(cls, left, right, obuf, oname, odesc):
        with Error() as err:
            hs = cls(_sfhash_intersect_hashsets(left.get(), right.get(), buf_beg(obuf, c_uint8), oname.encode('utf-8'), odesc.encode('utf-8'), byref(err.get())))
            if err:
                raise RuntimeError(str(err))
        return hs

    @classmethod
    def difference(cls, left, right, obuf, oname, odesc):
        with Error() as err:
            hs = cls(_sfhash_difference_hashsets(left.get(), right.get(), buf_beg(obuf, c_uint8), oname.encode('utf-8'), odesc.encode('utf-8'), byref(err.get())))
            if err:
                raise RuntimeError(str(err))
        return hs


class SizeSet(Handle):
    def __init__(self, info, buf):
        # isolate the hashes in the buffer
        sbeg = info.sizes_off
        send = sbeg + info.hashset_size * 64
        sdata = memoryview(buf)[sbeg:send]

        with Error() as err:
            super().__init__(_sfhash_load_sizeset(info.get(), *buf_range(sdata, c_char), byref(err.get())))
            if err:
                raise RuntimeError(str(err))

    def destroy(self):
        _sfhash_destroy_sizeset(self.handle)
        super().destroy()

    def __contains__(self, size):
        return _sfhash_lookup_sizeset(self.get(), size)


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


class Matcher(Handle):
    def __init__(self, lines):
        buf = lines.encode('utf-8')
        with Error() as err:
            super().__init__(_sfhash_create_matcher(*buf_range(buf, c_char), byref(err.get())))
            if err:
                raise RuntimeError(str(err))

    def destroy(self):
        _sfhash_destroy_matcher(self.handle)
        super().destroy()

    def has_size(self, size):
        return _sfhash_matcher_has_size(self.get(), size)

    def has_hash(self, h):
        return _sfhash_matcher_has_hash(self.get(), *buf_range(h, c_uint8))

    def has_filename(self, filename):
        return _sfhash_matcher_has_filename(self.get(), filename.encode('utf-8'))
