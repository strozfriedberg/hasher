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

empty_entropy = 0.0

lc_alphabet = b'abcdefghijklmnopqrstuvwxyz'

lc_alphabet_hashes = (
    "c3fcd3d76192e4007dfb496cca67e13b",
    "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
    "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
)

lc_alphabet_entropy = 4.700439718141092

abc = b'abc'

abc_hashes = (
    '900150983cd24fb0d6963f7d28e17f72',
    'a9993e364706816aba3e25717850c26c9cd0d89d',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
)

abc_entropy = 1.584962500721156


class TestHasher(unittest.TestCase):
    def hash_this(self, bufs, exp):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h:
            self.hash_it(h, bufs, exp)

    def hash_it(self, h, bufs, exp):
        # NB: getting the crypto hashes clears the internal hashers, so
        # to test both get_hashes() and get_hashes_dict() we must recompute
        for buf in bufs:
            h.update(buf)

        hashes = h.get_hashes()

        self.assertEqual(exp[0], bytes(hashes.md5).hex())
        self.assertEqual(exp[1], bytes(hashes.sha1).hex())
        self.assertEqual(exp[2], bytes(hashes.sha256).hex())

        h.reset()

        for buf in bufs:
            h.update(buf)

        hashes_dict = h.get_hashes_dict()

        exp_dict = {
            'md5': exp[0],
            'sha1': exp[1],
            'sha256': exp[2]
        }
        self.assertEqual(exp_dict, hashes_dict)

    def test_nothing(self):
        self.hash_this((), empty_hashes)

    def test_bytes_one_buffer(self):
        self.hash_this((lc_alphabet,), lc_alphabet_hashes)

    def test_memoryview_of_bytes_one_buffer(self):
        self.hash_this((memoryview(lc_alphabet),), lc_alphabet_hashes)

    def test_bytearray_one_buffer(self):
        self.hash_this((bytearray(lc_alphabet),), lc_alphabet_hashes)

    def test_memoryview_of_bytearray_one_buffer(self):
        self.hash_this((memoryview(bytearray(lc_alphabet)),), lc_alphabet_hashes)

    def test_bytes_two_buffers(self):
        self.hash_this((lc_alphabet[0:12], lc_alphabet[12:]), lc_alphabet_hashes)

    def test_bytearray_two_buffers(self):
        self.hash_this(
            (bytearray(lc_alphabet[0:15]), bytearray(lc_alphabet[15:])),
            lc_alphabet_hashes
        )

    def test_bytes_short(self):
        self.hash_this((abc,), abc_hashes)

    def test_memoryview_of_bytes_short(self):
        self.hash_this((memoryview(abc),), abc_hashes)

    def test_bytearray_short(self):
        self.hash_this((bytearray(abc),), abc_hashes)

    def test_memoryview_of_bytearray_short(self):
        self.hash_this((memoryview(bytearray(abc)),), abc_hashes)

    def test_reset_before_use(self):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h:
            h.reset()
            self.hash_it(h, (), empty_hashes)

    def test_reset_after_use(self):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h:
            self.hash_it(h, (lc_alphabet,), lc_alphabet_hashes)
            h.reset()
            self.hash_it(h, (), empty_hashes)

    def test_clone(self):
        with hasher.Hasher(hasher.MD5 | hasher.SHA1 | hasher.SHA256) as h1:
            self.hash_it(h1, (lc_alphabet,), lc_alphabet_hashes)
            with h1.clone() as h2:
                self.assertEqual(h1.get_hashes(), h2.get_hashes())


class TestEntropy(unittest.TestCase):
    def process_this(self, bufs, exp):
        with hasher.Hasher(hasher.ENTROPY) as h:
            self.process_it(h, bufs, exp)

    def process_it(self, h, bufs, exp):
        for buf in bufs:
            h.update(buf)

        self.assertEqual(exp, h.get_hashes().entropy)

        self.assertEqual({'entropy': round(exp, 3)}, h.get_hashes_dict())
        self.assertEqual({'entropy': round(exp, 6)}, h.get_hashes_dict(rounding=6))
        self.assertEqual({'entropy': exp}, h.get_hashes_dict(rounding=None))

    def test_entropy_nothing(self):
        self.process_this((), empty_entropy)

    def test_bytes_one_buffer(self):
        self.process_this((lc_alphabet,), lc_alphabet_entropy)

    def test_memoryview_of_bytes_one_buffer(self):
        self.process_this((memoryview(lc_alphabet),), lc_alphabet_entropy)

    def test_bytearray_one_buffer(self):
        self.process_this((bytearray(lc_alphabet),), lc_alphabet_entropy)

    def test_memoryview_of_bytearray_one_buffer(self):
        self.process_this((memoryview(bytearray(lc_alphabet)),), lc_alphabet_entropy)

    def test_bytes_two_buffers(self):
        self.process_this((lc_alphabet[0:12], lc_alphabet[12:]), lc_alphabet_entropy)

    def test_bytearray_two_buffers(self):
        self.process_this(
            (bytearray(lc_alphabet[0:15]), bytearray(lc_alphabet[15:])),
            lc_alphabet_entropy
        )

    def test_bytes_short(self):
        self.process_this((abc,), abc_entropy)

    def test_memoryview_of_bytes_short(self):
        self.process_this((memoryview(abc),), abc_entropy)

    def test_bytearray_short(self):
        self.process_this((bytearray(abc),), abc_entropy)

    def test_memoryview_of_bytearray_short(self):
        self.process_this((memoryview(bytearray(abc)),), abc_entropy)

    def test_reset_before_use(self):
        with hasher.Hasher(hasher.ENTROPY) as h:
            h.reset()
            self.process_it(h, (), empty_entropy)

    def test_reset_after_use(self):
        with hasher.Hasher(hasher.ENTROPY) as h:
            self.process_it(h, (lc_alphabet,), lc_alphabet_entropy)
            h.reset()
            self.process_it(h, (), empty_entropy)

    def test_clone(self):
        with hasher.Hasher(hasher.ENTROPY) as h1:
            self.process_it(h1, (lc_alphabet,), lc_alphabet_entropy)
            with h1.clone() as h2:
                self.assertEqual(h1.get_hashes(), h2.get_hashes())


class TestFuzzy(unittest.TestCase):
    def test_set_total_input_length(self):
        self.hash_this((lc_alphabet,), '3:u+6LO5Sfn:u+6LO5Sfn')

    def hash_this(self, bufs, exp):
        with hasher.Hasher(hasher.FUZZY) as h:
            self.hash_it(h, bufs, exp)

    def hash_it(self, h, bufs, exp):
        h.set_total_input_length(sum(len(x) for x in bufs))
        for buf in bufs:
            h.update(buf)

        self.assertEqual(exp, h.get_hashes().fuzzy)
        self.assertEqual({'fuzzy': exp}, h.get_hashes_dict())


class TestFuzzyMatcher(unittest.TestCase):
    def test_matches(self):
        data =  """ssdeep,1.1--blocksize:hash:hash,filename
6:S+W9pdFFwj+Q4HRhOhahxlA/FG65WOCWn9Q6Wg9r939:TmAgxho/r5Wun9Q6p9r9t,\"a.txt\"
6:S5O61sdFFwj+Q4HRhOhahxlA/FG65WOCWn9hy9r9eF:gmAgxho/r5Wun9o9r9a,\"b.txt\"
6:STLdFFwj+Q4HRhOhahxlA/FG65WOCWn9kKF9r9TKO:wLAgxho/r5Wun9k89r9TJ,\"c.txt\"
6:Sm5dFFwj+Q4HRhOhahxlA/FG65WOCWn9l2F9r9xI2O:T5Agxho/r5Wun9lI9r9xIl,\"d.txt\"
6:SDssdFFwj+Q4HRhOhahxlA/FG65WOCWn9nRk89r9KRkJ:YAgxho/r5Wun9RR9r9KRa,\"e.txt\"
6:SS7Lp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9nv7LZW9r9KzLZ3:T7LLAgxho/r5Wun9v7LZW9r9KzLZ3,\"f.txt\"
6:S8QLdFFwj+Q4HRhOhahxlA/FG65WOCWn91KRu9r9YlIv:XKAgxho/r5Wun91K89r9j,\"g.txt\"
6:SXp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9TF9r9a9O:m5Agxho/r5Wun9h9r9aU,\"h.txt\"
6:Si65dFFwj+Q4HRhOhahxlA/FG65WOCWn9rTF9r9iTO:q5Agxho/r5Wun919r9v,\"i.txt\"
6:SIJS5dFFwj+Q4HRhOhahxlA/FG65WOCWn9S6J7F9r9zBi7O:9JS5Agxho/r5Wun9H7F9r907O,\"j.txt\"
6:Sdcp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9n89r9WJ:Dp5Agxho/r5Wun9n89r9WJ,\"k.txt\"
6:SHHsdFFwj+Q4HRhOhahxlA/FG65WOCWn9oFF9r9HFO:SsAgxho/r5Wun9EF9r9lO,\"l.txt\"
6:SIoFsdFFwj+Q4HRhOhahxlA/FG65WOCWn9Ng9r9I9:9Agxho/r5Wun9a9r9k,\"m.txt\"
6:Scw/dFFwj+Q4HRhOhahxlA/FG65WOCWn9nhwg9r9K69:uAgxho/r5Wun999r9KG,\"n.txt\"
6:SY5dFFwj+Q4HRhOhahxlA/FG65WOCWn90F9r9VO:r5Agxho/r5Wun9a9r98,\"o.txt\""""
        self.maxDiff = None
        expected = {
            ('a.txt', '', 78),
            ('b.txt', '', 78),
            ('c.txt', '', 78),
            ('d.txt', '', 80),
            ('e.txt', '', 78),
            ('f.txt', '', 78),
            ('g.txt', '', 78),
            ('h.txt', '', 79),
            ('i.txt', '', 78),
            ('j.txt', '', 78),
            ('k.txt', '', 78),
            ('l.txt', '', 78),
            ('m.txt', '', 78),
            ('n.txt', '', 78),
            ('o.txt', '', 78),
        }
        with hasher.FuzzyMatcher(data) as matcher:
          hits = list(matcher.matches("6:S8y5dFFwj+Q4HRhOhahxlA/FG65WOCWn9M9r9Rg:Ty5Agxho/r5Wun9M9r9Rg"))
          self.assertEqual(15, len(hits))
          self.assertEqual(80, max(x[2] for x in hits))
          self.assertEqual(expected, set(hits))

    def test_match_filenames(self):
        data =  """ssdeep,1.1--blocksize:hash:hash,filename
786432:T48a50LQkKsHYLJAhbWOc82KY91w6aqotEtmS8Pjk9eQG9m/HA:TcXpsTlchVvlaqcEtmclo,"c63e39ef408023b2aa0cee507f5f4e56\""""

        with hasher.FuzzyMatcher(data) as matcher:
            hits = list(matcher.matches('786432:T48a50LQkKsHYLJAhbWOc82KY91w6aqotEtmS8Pjk9eQG9m/HA:TcXpsTlchVvlaqcEtmclo,"c:\MSOCache\All Users\Access.en-us\AccLR.cab"'))
            self.assertEqual([('c63e39ef408023b2aa0cee507f5f4e56', r'c:\MSOCache\All Users\Access.en-us\AccLR.cab', 100)], hits)


if __name__ == "__main__":
    unittest.main()
