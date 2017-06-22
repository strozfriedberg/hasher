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
                ('sha256', c_uint8 * 32)]

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.md5[:] == other.md5[:] and
                    self.sha1[:] == other.sha1[:] and
                    self.sha256[:] == other.sha256[:])
        return NotImplemented

    def __ne__(self, other):
        return not self == other


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


MD5    = 1 << 0
SHA1   = 1 << 1
SHA256 = 1 << 2


class Hasher(object):
    def __init__(self, algs, clone=None):
        self.hasher = _sfhash_clone_hasher(clone) if clone else _sfhash_create_hasher(algs)

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
        blen = len(buf)

        if blen < 8:
            # ctypes from_buffer and from_buffer_copy require at least 8 bytes
            tmp = bytearray(8)
            tmp[0:blen] = buf
            buf = tmp

        if isinstance(buf, bytes):
            buf = (c_uint8 * len(buf)).from_buffer_copy(buf)
        elif isinstance(buf, bytearray):
            buf = (c_uint8 * len(buf)).from_buffer(buf)
       
        beg = addressof(buf) 
        end = cast(beg + blen, c_void_p)
        _sfhash_update_hasher(self.hasher, beg, end)

    def reset(self):
        _sfhash_reset_hasher(self.hasher)

    def get_hashes(self):
        h = HasherHashes()
        _sfhash_get_hashes(self.hasher, byref(h))
        return h
