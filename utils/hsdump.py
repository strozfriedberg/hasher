#!/usr/bin/python3

# dumps the hashes of a hashset as hexadecimal strings

import mmap
import sys

import hasher

with open(sys.argv[1], 'rb') as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mbuf:
        with hasher.HashSetInfo(mbuf) as hsinfo:
            i = hsinfo.hashset_off
            end = i + hsinfo.hash_length * hsinfo.hashset_size
            while i < end:
                print(mbuf[i:i+hsinfo.hash_length].hex())
                i += hsinfo.hash_length
