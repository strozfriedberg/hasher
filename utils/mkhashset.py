#!/usr/bin/python3

# Make a hashset from a list of filenames:
#
# find -type f | xargs sha1sum | cut -f1 -d' ' | sort -u | ./mkhashset.py SHA-1 'Some test hashes' 'These are test hashes.' >sha1.hset
#
#
# Make a hashset and sizeset from a list of filenames:
#
# for i in  $(find -type f); do echo $(sha1sum $i) $(stat --printf=%s $i) ; done | cut -f1,3 -d' ' | sort -u | ./mkhashset.py SHA-1 'Some test hashes' 'These are test hashes.' >sha1.hset
#
#
# Make a hashset and sizeset from the NSRL:
#
# for i in NSRLFile.*.txt.gz ; do zcat $i | ./nsrldump.py ; done | ./mkhashset.py SHA-1 'NSRL' 'The NSRL!' >nsrl.hset
#

import datetime
import hashlib
import sys


HASH_TYPE = {
    'md5':       1 <<  0,
    'sha1':      1 <<  1,
    'sha2_224':  1 <<  2,
    'sha2_256':  1 <<  3,
    'sha2_384':  1 <<  4,
    'sha2_512':  1 <<  5,
    'sha3_224':  1 <<  6,
    'sha3_256':  1 <<  7,
    'sha3_384':  1 <<  8,
    'sha3_512':  1 <<  9,
    'blake3':    1 << 10,
    'quick_md5': 1 << 13,
    'other':     1 <  31
}


def nonempty_lines(src):
    for line in src:
        line = line.strip()
        if line:
            yield line


def expected_index(h, set_size):
    high32 = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]
    return (high32 * set_size) >> 32


def write_cstring(b, field_width, buf):
    wlen = buf.write(b)
    wlen += buf.write(b'\0' * (field_width - len(b)))
    return wlen


def run(hash_type, hashset_name, hashset_desc, inlines, outbuf):
    hash_type = HASH_TYPE[hash_type]

    hashset_name = hashset_name.encode('UTF-8')
    hashset_desc = hashset_desc.encode('UTF-8')

    hashset_name_field_len = 96
    hashset_desc_field_len = 512

    # reject overlong strings before we do any work
    if len(hashset_name) + 1 > hashset_name_field_len:
        raise RuntimeError('hashset name too long')

    if len(hashset_desc) + 1 > hashset_desc_field_len:
        raise RuntimeError('hashset description too long')

    version = 1
    flags = 0

    hashes = []
    sizes = []

    for line in nonempty_lines(inlines):
        cols = line.split(' ')
        hashes.append(bytes.fromhex(cols[0]))
        if len(cols) == 2:
            sizes.append(int(cols[1]))

    if len(hashes) != len(sizes) and sizes:
        raise RuntimeError('some sizes missing')

    hash_length = len(hashes[0])

    max_delta = 0
    for i, h in enumerate(hashes):
        ei = expected_index(h, len(hashes))
        max_delta = max(max_delta, abs(i - ei))

    hashset = b''.join(hashes)
    hasher = hashlib.sha256()
    hasher.update(hashset)

    hashes_off = 4096
    sizes_off = hashes_off + len(hashes)*hash_length if sizes else 0

    timestamp = datetime.datetime.now().isoformat(timespec='microseconds').encode('UTF-8')
    timestamp_field_len = 40

    pos = 0
    pos += outbuf.write(b'SetOHash')
    pos += outbuf.write(version.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(flags.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hash_type.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hash_length.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(len(hashes).to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hashes_off.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(sizes_off.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(max_delta.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hasher.digest())
    pos += write_cstring(hashset_name, hashset_name_field_len, outbuf)
    pos += write_cstring(timestamp, timestamp_field_len, outbuf)
    pos += write_cstring(hashset_desc, hashset_desc_field_len, outbuf)
    pos += outbuf.write(b'\0' * (hashes_off-pos))
    pos += outbuf.write(hashset)

    if sizes:
        pos += outbuf.write(b'\0' * (sizes_off-pos))
        for s in sizes:
            pos += outbuf.write(s.to_bytes(8, 'little', signed=False))


if __name__ == "__main__":
    run(*sys.argv[1:4], sys.stdin, sys.stdout.buffer)   # pylint: disable=no-value-for-parameter
