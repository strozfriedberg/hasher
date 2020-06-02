#!/usr/bin/python3

# dumps the metadata of a hashset

import mmap
import sys

import hasher


with open(sys.argv[1], 'rb') as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mbuf:
        with hasher.HashSetInfo(mbuf) as hsinfo:
            print(f'version: {hsinfo.version}')
            print(f'hash type: {hsinfo.hash_type}')
            print(f'hash length: {hsinfo.hash_length}')
            print(f'flags: {hsinfo.flags}')
            print(f'hashset size: {hsinfo.hashset_size}')
            print(f'hashset offset: {hsinfo.hashset_off}')
            print(f'sizes offset: {hsinfo.sizes_off}')
            print(f'radius: {hsinfo.radius}')
            print(f'hashset SHA256: {bytes(hsinfo.hashset_sha256).hex()}')
            print(f'hashset name: {hsinfo.hashset_name.decode("utf-8")}')
            print(f'hashset time: {hsinfo.hashset_time.decode("utf-8")}')
            print(f'hashset description: {hsinfo.hashset_desc.decode("utf-8")}')
