#!/usr/bin/python3

import os
import unittest

import hasher

# ensure cwd is the dir containing this file
os.chdir(os.path.dirname(os.path.realpath(__file__)))


empty_hashes = (
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

lc_alphabet = b'abcdefghijklmnopqrstuvwxyz'

lc_alphabet_hashes = (
    "c3fcd3d76192e4007dfb496cca67e13b",
    "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
    "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
)

abc = b'abc'

abc_hashes = (
    '900150983cd24fb0d6963f7d28e17f72',
    'a9993e364706816aba3e25717850c26c9cd0d89d',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
)


class TestHasher(unittest.TestCase):
    def hash_this(self, bufs, exp):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h:
            self.hash_it(h, bufs, exp)

    def hash_it(self, h, bufs, exp):
        for buf in bufs:
            h.update(buf)

        hashes = h.get_hashes()

        self.assertEqual(exp[0], bytes(hashes.md5).hex())
        self.assertEqual(exp[1], bytes(hashes.sha1).hex())
        self.assertEqual(exp[2], bytes(hashes.sha256).hex())

    def test_hash_nothing(self):
        self.hash_this((), empty_hashes)

    def test_hash_bytes_one_buffer(self):
        self.hash_this((lc_alphabet,), lc_alphabet_hashes)

    def test_hash_bytearray_one_buffer(self):
        self.hash_this((bytearray(lc_alphabet),), lc_alphabet_hashes)

    def test_hash_bytes_two_buffers(self):
        self.hash_this((lc_alphabet[0:12], lc_alphabet[12:]), lc_alphabet_hashes)

    def test_hash_bytearray_two_buffers(self):
        self.hash_this(
            (bytearray(lc_alphabet[0:15]), bytearray(lc_alphabet[15:])),
            lc_alphabet_hashes
        )

    def test_hash_bytes_short(self):
        self.hash_this((abc,), abc_hashes)

    def test_hash_bytes_short(self):
        self.hash_this((bytearray(abc),), abc_hashes)

    def test_hash_reset_before_use(self):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h:
            h.reset()
            self.hash_it(h, (), empty_hashes)

    def test_hash_reset_after_use(self):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h:
            self.hash_it(h, (lc_alphabet,), lc_alphabet_hashes)
            h.reset()
            self.hash_it(h, (), empty_hashes)

    def test_hash_clone(self):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h1:
            self.hash_it(h1, (lc_alphabet,), lc_alphabet_hashes)
            with h1.clone() as h2:
                self.assertEqual(h1.get_hashes(), h2.get_hashes())


if __name__ == "__main__":
    unittest.main()
