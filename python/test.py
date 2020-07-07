#!/usr/bin/python3

import ctypes
import mmap
import os
import unittest

import hasher

# ensure cwd is the dir containing this file
os.chdir(os.path.dirname(os.path.realpath(__file__)))


empty_hashes = {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha2_256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha3_256": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    "quick_md5": "d41d8cd98f00b204e9800998ecf8427e",
}

empty_entropy = 0.0

lc_alphabet = b'abcdefghijklmnopqrstuvwxyz'

lc_alphabet_hashes = {
    "md5": "c3fcd3d76192e4007dfb496cca67e13b",
    "sha1": "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
    "sha2_256": "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
    "sha3_256": "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521",
    "blake3": "2468eec8894acfb4e4df3a51ea916ba115d48268287754290aae8e9e6228e85f",
    "quick_md5": "c3fcd3d76192e4007dfb496cca67e13b",
}

lc_alphabet_entropy = 4.700439718141092

abc = b'abc'

abc_hashes = {
    "md5": "900150983cd24fb0d6963f7d28e17f72",
    "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
    "sha2_256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha3_256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    "quick_md5": "900150983cd24fb0d6963f7d28e17f72",
}

abc_entropy = 1.584962500721156


class HasherTestCase(unittest.TestCase):
    ALGS = None

    def hash_this(self, bufs, exp):
        with hasher.Hasher(self.ALGS) as h:
            self.hash_it(h, bufs, exp)

    def hash_it(self, h, bufs, exp):
        for buf in bufs:
            h.update(buf)
        hashes = h.get_hashes()

        exp_h = hasher.HasherHashes.from_dict(exp)

        self.assertEqual(exp_h, hashes)
        self.assertEqual(exp, hashes.to_dict(self.ALGS))


class TestHasher(HasherTestCase):
    ALGS = hasher.MD5 | hasher.SHA1 | hasher.SHA2_256 | hasher.SHA3_256 | hasher.BLAKE3 | hasher.QUICK_MD5
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
        with hasher.Hasher(self.ALGS) as h:
            h.reset()
            self.hash_it(h, (), empty_hashes)

    def test_reset_after_use(self):
        with hasher.Hasher(self.ALGS) as h:
            self.hash_it(h, (lc_alphabet,), lc_alphabet_hashes)
            h.reset()
            self.hash_it(h, (), empty_hashes)

    def test_clone(self):
        with hasher.Hasher(self.ALGS) as h1:
            self.hash_it(h1, (lc_alphabet,), lc_alphabet_hashes)
            with h1.clone() as h2:
                self.assertEqual(h1.get_hashes(), h2.get_hashes())


class TestQuickHasher(HasherTestCase):
    ALGS = hasher.MD5 | hasher.QUICK_MD5

    def test_quick_md5_long(self):
        buf = b'1234567890' * 100
        exp = {
            'md5': 'f1257a8659eb92d36fe14c6bf3852a6a',
            'quick_md5': '9684119054ad908143a677b4db00495f',
        }
        self.hash_this([buf], exp)

    def test_quick_md5_short(self):
        buf = b'a' * 256
        exp = {
            'md5': '81109eec5aa1a284fb5327b10e9c16b9',
            'quick_md5': '81109eec5aa1a284fb5327b10e9c16b9',
        }
        self.hash_this([buf], exp)


class TestEntropy(unittest.TestCase):
    def process_this(self, bufs, exp):
        with hasher.Hasher(hasher.ENTROPY) as h:
            self.process_it(h, bufs, exp)

    def process_it(self, h, bufs, exp):
        for buf in bufs:
            h.update(buf)

        hashes = h.get_hashes()

        self.assertEqual(exp, hashes.entropy)

        self.assertEqual(
            hasher.HasherHashes.from_dict({'entropy': exp}),
            hashes
        )

        self.assertEqual(
            {'entropy': round(exp, 3)},
            hashes.to_dict(hasher.ENTROPY)
        )
        self.assertEqual(
            {'entropy': round(exp, 6)},
            hashes.to_dict(hasher.ENTROPY, rounding=6)
        )
        self.assertEqual(
            {'entropy': exp},
            hashes.to_dict(hasher.ENTROPY, rounding=None)
        )

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

        hashes = h.get_hashes()

        exp_d = {'fuzzy': exp}
        self.assertEqual(hasher.HasherHashes.from_dict(exp_d), hashes)
        self.assertEqual(exp_d, hashes.to_dict(hasher.FUZZY))


class TestFuzzyMatcher(unittest.TestCase):
    def test_matches(self):
        data = r'''ssdeep,1.1--blocksize:hash:hash,filename
6:S+W9pdFFwj+Q4HRhOhahxlA/FG65WOCWn9Q6Wg9r939:TmAgxho/r5Wun9Q6p9r9t,"a.txt"
6:S5O61sdFFwj+Q4HRhOhahxlA/FG65WOCWn9hy9r9eF:gmAgxho/r5Wun9o9r9a,"b.txt"
6:STLdFFwj+Q4HRhOhahxlA/FG65WOCWn9kKF9r9TKO:wLAgxho/r5Wun9k89r9TJ,"c.txt"
6:Sm5dFFwj+Q4HRhOhahxlA/FG65WOCWn9l2F9r9xI2O:T5Agxho/r5Wun9lI9r9xIl,"d.txt"
6:SDssdFFwj+Q4HRhOhahxlA/FG65WOCWn9nRk89r9KRkJ:YAgxho/r5Wun9RR9r9KRa,"e.txt"
6:SS7Lp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9nv7LZW9r9KzLZ3:T7LLAgxho/r5Wun9v7LZW9r9KzLZ3,"f.txt"
6:S8QLdFFwj+Q4HRhOhahxlA/FG65WOCWn91KRu9r9YlIv:XKAgxho/r5Wun91K89r9j,"g.txt"
6:SXp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9TF9r9a9O:m5Agxho/r5Wun9h9r9aU,"h.txt"
6:Si65dFFwj+Q4HRhOhahxlA/FG65WOCWn9rTF9r9iTO:q5Agxho/r5Wun919r9v,"i.txt"
6:SIJS5dFFwj+Q4HRhOhahxlA/FG65WOCWn9S6J7F9r9zBi7O:9JS5Agxho/r5Wun9H7F9r907O,"j.txt"
6:Sdcp5dFFwj+Q4HRhOhahxlA/FG65WOCWn9n89r9WJ:Dp5Agxho/r5Wun9n89r9WJ,"k.txt"
6:SHHsdFFwj+Q4HRhOhahxlA/FG65WOCWn9oFF9r9HFO:SsAgxho/r5Wun9EF9r9lO,"l.txt"
6:SIoFsdFFwj+Q4HRhOhahxlA/FG65WOCWn9Ng9r9I9:9Agxho/r5Wun9a9r9k,"m.txt"
6:Scw/dFFwj+Q4HRhOhahxlA/FG65WOCWn9nhwg9r9K69:uAgxho/r5Wun999r9KG,"n.txt"
6:SY5dFFwj+Q4HRhOhahxlA/FG65WOCWn90F9r9VO:r5Agxho/r5Wun9a9r98,"o.txt"'''
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
        data =  r'''ssdeep,1.1--blocksize:hash:hash,filename
786432:T48a50LQkKsHYLJAhbWOc82KY91w6aqotEtmS8Pjk9eQG9m/HA:TcXpsTlchVvlaqcEtmclo,"c63e39ef408023b2aa0cee507f5f4e56"'''

        with hasher.FuzzyMatcher(data) as matcher:
            hits = list(matcher.matches(r'786432:T48a50LQkKsHYLJAhbWOc82KY91w6aqotEtmS8Pjk9eQG9m/HA:TcXpsTlchVvlaqcEtmclo,"c:\MSOCache\All Users\Access.en-us\AccLR.cab"'))
            self.assertEqual([('c63e39ef408023b2aa0cee507f5f4e56', r'c:\MSOCache\All Users\Access.en-us\AccLR.cab', 100)], hits)


class TestMatcher(unittest.TestCase):
    def test_match_bad(self):
        data = "bogus bogus\tbogus\tnonsense"
        with self.assertRaises(RuntimeError):
            with hasher.Matcher(data) as matcher:
                pass


    def test_match_good(self):
        data = (
            "Davout\t521\t375d38e640ae802b4d95468af1e8780ed7fbbf04\n"
            "Soult\t768\te3cc51c54197fdcd477a73e7f8a0b6b55eaa8478\n"
            "Ney\t12344565\t5e810a94c86ff057849bfa992bd176d8f743d160\n"
        )

        with hasher.Matcher(data) as matcher:
            self.assertTrue(matcher.has_filename("Davout"))
            self.assertFalse(matcher.has_filename("Bernadotte"))

            self.assertTrue(matcher.has_size(12344565))
            self.assertFalse(matcher.has_size(0))
            self.assertFalse(matcher.has_size(522))

            self.assertTrue(matcher.has_hash(bytes.fromhex('5e810a94c86ff057849bfa992bd176d8f743d160')))
            self.assertFalse(matcher.has_hash(bytes.fromhex('0000000000000000000000000000000000000000')))


class TestHashSetAPI(unittest.TestCase):
    def test_hashset_info_bad(self):
        data = "bogus bogus bogus nonsense".encode('utf-8')
        with self.assertRaises(RuntimeError):
            with hasher.HashSetInfo(data) as matcher:
                pass

    def test_hashset_info_good(self):
        with open('../test/test1.hset', 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                # check the info
                with hasher.HashSetInfo(buf) as info:
                    self.assertEqual(1, info.version)
                    self.assertEqual(hasher.SHA1, info.hash_type)
                    self.assertEqual(20, info.hash_length)
                    self.assertEqual(0, info.flags)
                    self.assertEqual(100, info.hashset_size)
                    self.assertEqual(4096, info.hashset_off)
                    self.assertEqual(6096, info.sizes_off)
                    self.assertEqual(10, info.radius)
                    self.assertEqual(bytes.fromhex('26ade256a8ae8d6307cfbdc224bdfa320abdf6259a6944691613701237e751e4'), bytes(info.hashset_sha256))
                    self.assertEqual(b'Some test hashes', info.hashset_name)
                    self.assertEqual(b'2020-02-12T11:58:19.910221', info.hashset_time)
                    self.assertEqual(b'These are test hashes.', info.hashset_desc)

                    # check the hashset
                    with hasher.HashSetData(info, buf) as hset:
                        self.assertTrue(bytes.fromhex('55250d55d5bb84d127e34bde24ea32d86a4d1584') in hset)
                        self.assertTrue(bytes.fromhex('fc824043658c86424b5f2d480134dce7b004143d') in hset)
                        self.assertFalse(bytes.fromhex('baaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaad') in hset)

                    # check the sizeset
                    with hasher.SizeSet(info, buf) as sset:
                        self.assertTrue(6140 in sset)
                        self.assertTrue(115 in sset)
                        self.assertFalse(1234567 in sset)

    def test_hashset_setops(self):
        with open('../test/0123456789_a.hset', 'rb') as af, \
             open('../test/0123456789_b.hset', 'rb') as bf:
            with mmap.mmap(af.fileno(), 0, access=mmap.ACCESS_READ) as abuf, \
                 mmap.mmap(bf.fileno(), 0, access=mmap.ACCESS_READ) as bbuf:
                with hasher.HashSet.load(abuf) as a, \
                     hasher.HashSet.load(bbuf) as b:

                    # check union
                    outfile = 'a_union_b.hset'
                    with open(outfile, 'w+b') as of:
                        omaxsize = 4096 + a.info().hashset_size * a.info().hash_length + b.info().hashset_size * b.info().hash_length
                        os.ftruncate(of.fileno(), omaxsize)
                        with mmap.mmap(of.fileno(), 0, access=mmap.ACCESS_WRITE) as obuf:
                            with hasher.HashSet.union(a, b, obuf, "a union b", "test of a union b") as o:
                                oactualsize = o.info().hashset_off + o.info().hashset_size * o.info().hash_length

                                self.assertEqual(2, o.info().hashset_size)
                                self.assertTrue(bytes.fromhex('84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7881') in o)
                                self.assertTrue(bytes.fromhex('84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882') in o)

                        os.ftruncate(of.fileno(), oactualsize)

                    os.remove(outfile)

                    # check intersection
                    outfile = 'a_intersect_b.hset'
                    with open(outfile, 'w+b') as of:
                        omaxsize = 4096 + max(a.info().hashset_size, b.info().hashset_size) * a.info().hash_length
                        os.ftruncate(of.fileno(), omaxsize)
                        with mmap.mmap(of.fileno(), 0, access=mmap.ACCESS_WRITE) as obuf:
                            with hasher.HashSet.intersect(a, b, obuf, "a intersect b", "test of a intersect b") as o:
                                oactualsize = o.info().hashset_off + o.info().hashset_size * o.info().hash_length

                                self.assertEqual(1, o.info().hashset_size)
                                self.assertTrue(bytes.fromhex('84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882') in o)

                        os.ftruncate(of.fileno(), oactualsize)

                    os.remove(outfile)

                    # check difference
                    outfile = 'a_minus_b.hset'
                    with open(outfile, 'w+b') as of:
                        omaxsize = 4096 + a.info().hashset_size * a.info().hash_length
                        os.ftruncate(of.fileno(), omaxsize)
                        with mmap.mmap(of.fileno(), 0, access=mmap.ACCESS_WRITE) as obuf:
                            with hasher.HashSet.difference(a, b, obuf, "a minus b", "test of a minus b") as o:
                                oactualsize = o.info().hashset_off + o.info().hashset_size * o.info().hash_length

                                self.assertEqual(0, o.info().hashset_size)

                        os.ftruncate(of.fileno(), oactualsize)

                    os.remove(outfile)


class HashNameTest(unittest.TestCase):
    def test_hash_name(self):
        self.assertEqual('MD5', hasher.hash_name(hasher.MD5))


if __name__ == "__main__":
    unittest.main()
