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


def write_cstring(b, field_width, buf):
    wlen = buf.write(b)
    wlen += buf.write(b'\0' * (field_width - len(b)))
    return wlen


def write_le_u64(i, buf):
    return buf.write(i.to_bytes(8, 'little', signed=False))


def write_chunk(chunk_type, chunk_bytes, outbuf):
    wlen = write_le_u64(len(chunk_bytes), outbuf)
    wlen += outbuf.write(chunk_type)
    wlen += outbuf.write(chunk_bytes)
    
    hasher = hashlib.sha256()
    hasher.update(chunk_bytes)
    wlen += outbuf.write(hasher.digest())

    return wlen


def write_magic(outbuf):
    return outbuf.write(b'SetOHash')


def write_fhdr(version, hashset_name, hashset_name_field_len, hashset_desc, hashset_desc_field_len, timestamp, timestamp_field_len, outbuf):
    chbuf = io.BytesIO()
    write_le_u64(version, chbuf)
    write_cstring(hashset_name, hashset_name_field_len, chbuf)
    write_cstring(timestamp, timestamp_field_len, chbuf)
    write_cstring(hashset_desc, hashset_desc_field_len, chbuf)

    return write_chunk(b'FHDR', chbuf.getbuffer(), outbuf)


def write_hhdr(hash_type, hash_type_name, hash_type_name_field_len, hash_length, hash_count, outbuf):
    chbuf = io.BytesIO()
    write_le_u64(hash_type, chbuf)
    write_cstring(hash_type_name, hash_type_name_field_len, chbuf)
    write_le_u64(hash_length, chbuf)
    write_le_u64(hash_count, chbuf)
    
    return write_chunk(b'HHDR', chbuf.getbuffer(), outbuf)


def write_hdat(hashes, outbuf):
    return write_chunk(b'HDAT', b''.join(hashes), outbuf)


def write_fend(outbuf):
    return write_chunk(b'FEND', b'', outbuf)


def run(hash_type_name, hashset_name, hashset_desc, inlines, outbuf):
    hash_type = HASH_TYPE.get(hash_type_name, HASH_TYPE['other'])

    hashset_name = hashset_name.encode('UTF-8')
    hashset_desc = hashset_desc.encode('UTF-8')
    hash_type_name = hash_type_name.encode('UTF-8')

# TODO: use variable-length strings?
    hashset_name_field_len = 96
    hashset_desc_field_len = 512
    hash_type_name_field_len = 64 

    # reject overlong strings before we do any work
    if len(hashset_name) + 1 > hashset_name_field_len:
        raise RuntimeError('hashset name too long')

    if len(hashset_desc) + 1 > hashset_desc_field_len:
        raise RuntimeError('hashset description too long')

    if len(hash_type_name) + 1 > hashset_desc_field_len:
        raise RuntimeError('hashset type name too long')

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
    timestamp = datetime.datetime.now().isoformat(timespec='microseconds').encode('UTF-8')
    timestamp_field_len = 40

    pos = 0

    # Magic
    pos += write_magic(outbuf)

    # FHDR
    pos += write_fhdr(
        version,
        hashset_name,
        hashset_name_field_len,
        hashset_desc,
        hashset_desc_field_len,
        timestamp,
        timestamp_field_len,
        outbuf
    )

    # HHDR
    pos += write_hhdr(
        hash_type,
        hash_type_name,
        hash_type_name_field_len,
        hash_length,
        len(hashes),
        outbuf
    )

    # HDAT
    pos += write_hdat(hashes, outbuf)

    # FEND
    pos += write_fend(outbuf)


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
