#!/usr/bin/python3

#
# Make a hashset from a list of filenames:
#
# find | xargs sha1sum | cut -f1 -d' ' | sort -u | ./mkhashset.py SHA1 'Some test hashes' 'These are test hashes.' >sha1.hset
#

#
# Make a hashset from the NSRL:
#
# for i in NSRLFile.*.txt.gz ; do zcat $i | awk -F',' '{print $1}' | tail -n +2 ; done | cut -b 2-41 | ./mkhashset.py SHA1 'NSRL' 'The NSRL!' >nsrl.hset
#

import datetime
import hashlib
import sys


HASH_TYPE = {
    'Other':      0,
    'MD5':        1,
    'SHA-1':      2,
    'SHA-2-224':  3,
    'SHA-2-256':  4,
    'SHA-2-384':  5,
    'SHA-2-512':  6,
    'SHA-3-224':  7,
    'SHA-3-256':  8,
    'SHA-3-384':  9,
    'SHA-3-512': 10
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

    hashes = [bytes.fromhex(line) for line in nonempty_lines(inlines)]
    hash_length = len(hashes[0])

    max_delta = 0
    for i, h in enumerate(hashes):
        ei = expected_index(h, len(hashes))
        max_delta = max(max_delta, abs(i - ei))

    hashset = b''.join(hashes)
    hasher = hashlib.sha256()
    hasher.update(hashset)

    timestamp = datetime.datetime.now().isoformat(timespec='microseconds').encode('UTF-8')
    timestamp_field_len = 40

    pos = 0
    pos += outbuf.write(b'SetOHash')
    pos += outbuf.write(version.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(flags.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hash_type.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hash_length.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(len(hashes).to_bytes(8, 'little', signed=False))
    pos += outbuf.write(int(4096).to_bytes(8, 'little', signed=False))
    pos += outbuf.write(int(0).to_bytes(8, 'little', signed=False))
    pos += outbuf.write(max_delta.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hasher.digest())
    pos += write_cstring(hashset_name, hashset_name_field_len, outbuf)
    pos += write_cstring(timestamp, timestamp_field_len, outbuf)
    pos += write_cstring(hashset_desc, hashset_desc_field_len, outbuf)
    pos += outbuf.write(b'\0' * (4096-pos))
    pos += outbuf.write(hashset)


if __name__ == "__main__":
    run(*sys.argv[1:4], sys.stdin, sys.stdout.buffer)
