#!/usr/bin/python3

"""
Make a hashset from a list of filenames:

find -type f | xargs sha1sum | cut -f1 -d' ' | sort -u | ./mkhashset.py sha1 'Some test hashes' 'These are test hashes.' >sha1.hset

"""
import argparse
import datetime
import hashlib
import io
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


def write_pstring(s, out):
    b = s.encode('UTF-8')
    wlen = write_le_u16(len(b), out)
    wlen += out.write(b)
    return wlen


def write_le_u16(i, out):
    return out.write(i.to_bytes(2, 'little', signed=False))


def write_le_u64(i, out):
    return out.write(i.to_bytes(8, 'little', signed=False))


def write_chunk(chunk_type, chunk_bytes, out):
    wlen = write_le_u64(len(chunk_bytes), out)
    wlen += out.write(chunk_type)
    wlen += out.write(chunk_bytes)

    hasher = hashlib.sha256()
    hasher.update(chunk_bytes)
    wlen += out.write(hasher.digest())

    return wlen


def write_magic(out):
    return out.write(b'SetOHash')


def write_fhdr(version, hashset_name, hashset_desc, timestamp, out):
    chbuf = io.BytesIO()
    write_le_u64(version, chbuf)
    write_pstring(hashset_name, chbuf)
    write_pstring(timestamp, chbuf)
    write_pstring(hashset_desc, chbuf)

    return write_chunk(b'FHDR', chbuf.getbuffer(), out)


def write_hhdr(hash_type, hash_type_name, hash_length, hash_count, out):
    chbuf = io.BytesIO()
    write_le_u64(hash_type, chbuf)
    write_pstring(hash_type_name, chbuf)
    write_le_u64(hash_length, chbuf)
    write_le_u64(hash_count, chbuf)

    return write_chunk(b'HHDR', chbuf.getbuffer(), out)


def write_hdat(hashes, out):
    return write_chunk(b'HDAT', b''.join(hashes), out)


def write_fend(out):
    return write_chunk(b'FEND', b'', out)


def run(hash_type_name, hashset_name, hashset_desc, inlines, out):
    hash_type = HASH_TYPE.get(hash_type_name, HASH_TYPE['other'])

    version = 2

    # read the input
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

    # set the timestamp
    timestamp = datetime.datetime.now().isoformat(timespec='microseconds')

    pos = 0

    # Magic
    pos += write_magic(out)

    # FHDR
    pos += write_fhdr(version, hashset_name, hashset_desc, timestamp, out)

    # HHDR
    pos += write_hhdr(hash_type, hash_type_name, hash_length, len(hashes), out)

    # HDAT
    pos += write_hdat(hashes, out)

    # FEND
    pos += write_fend(out)

    print(f'wrote {pos} bytes', file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("hash_type", help="Hash type")
    parser.add_argument("hashset_name", help="Name of hash set")
    parser.add_argument("hashset_desc", help="Hash set description")
    args = parser.parse_args()
    run(
        args.hash_type,
        args.hashset_name,
        args.hashset_desc,
        sys.stdin,
        sys.stdout.buffer
    )
