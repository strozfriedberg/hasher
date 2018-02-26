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
                ('fuzzy', c_uint8 * 148),
                ('entropy', c_double)]

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.md5[:] == other.md5[:] and
                    self.sha1[:] == other.sha1[:] and
                    self.sha256[:] == other.sha256[:] and
                    self.entropy == other.entropy)
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self == other
        return NotImplemented


# SFHASH_Hasher* sfhash_create_hasher(uint32_t hashAlgs);
_sfhash_create_hasher = _hasher.sfhash_create_hasher
_sfhash_create_hasher.argtypes = [c_uint32]
_sfhash_create_hasher.restype = c_void_p

# SFHASH_Hasher* sfhash_clone_hasher(const SFHASH_Hasher* hasher);
_sfhash_clone_hasher = _hasher.sfhash_clone_hasher
_sfhash_clone_hasher.argtypes = [c_void_p]
_sfhash_clone_hasher.restype = c_void_p

# void sfhash_update_hasher(SFHASH_Hasher* hasher, const void* beg, const void* end)
_sfhash_update_hasher = _hasher.sfhash_update_hasher
_sfhash_update_hasher.argtypes = [c_void_p, c_void_p, c_void_p]
_sfhash_update_hasher.restype = None

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


MD5     = 1 << 0
SHA1    = 1 << 1
SHA256  = 1 << 2
ENTROPY = 1 << 3


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

    def reset(self):
        _sfhash_reset_hasher(self.hasher)

    def get_hashes(self):
        h = HasherHashes()
        _sfhash_get_hashes(self.hasher, byref(h))
        return h
