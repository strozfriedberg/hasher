#!/usr/bin/python3

"""
Make a hashset from a list of filenames:

find -type f | xargs sha1sum | cut -f1 -d' ' | ./mkhashset.py 'Some test hashes' 'These are test hashes.' sha1 >sha1.hset

Make a hashset and sizeset from a list of filenames:

for i in $(find -type f) ; do echo $(stat --printf=%s $i) $(md5sum $i | cut -f1 -d' ') $(sha1sum $i | cut -f1 -d' ') ; done | ./mkhashset.py 'Some test hashes' 'These are test hashes.' sizes md5 sha1 >test.hset

Make a hashset and sizeset from the NSRL:

for i in NSRLFile.*.txt.gz ; do zcat $i | ./nsrldump.py ; done | ./mkhashset.py 'NSRL' 'The NSRL!' sha1 >nsrl.hset
"""
import argparse
import datetime
import hashlib
import io
import sys


class HashInfo(object):
    def __init__(self, hash_type, hash_name, hash_length):
        self.type = hash_type
        self.name = hash_name
        self.length = hash_length


SIZES = 0
MD5 = 1
SHA1 = 2
SHA2_224 = 3
SHA2_256 = 4
SHA2_384 = 5
SHA2_512 = 6
SHA3_224 = 7
SHA3_256 = 8
SHA3_384 = 9
SHA3_512 = 10
BLAKE3 = 11
OTHER = 0xFFFF


HASH_INFO = {
    'sizes':    HashInfo(SIZES, 'sizes', 8),
    'md5':      HashInfo(MD5, 'md5', 16),
    'sha1':     HashInfo(SHA1, 'sha1', 20),
    'sha2_224': HashInfo(SHA2_224, 'sha2_224', 28),
    'sha2_256': HashInfo(SHA2_256, 'sha2_256', 32),
    'sha2_384': HashInfo(SHA2_384, 'sha2_384', 48),
    'sha2_512': HashInfo(SHA2_512, 'sha2_512', 64),
    'sha3_224': HashInfo(SHA3_224, 'sha3_224', 28),
    'sha3_256': HashInfo(SHA3_256, 'sha3_256', 32),
    'sha3_384': HashInfo(SHA3_384, 'sha3_384', 48),
    'sha3_512': HashInfo(SHA3_512, 'sha3_512', 64),
    'blake3':   HashInfo(BLAKE3, 'blake3', 32),
# TODO: make sure other works
    'other':    HashInfo(OTHER, None, None)
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


def to_le_u16(i):
    return i.to_bytes(2, 'little', signed=False)


def to_be_u16(i):
    return i.to_bytes(2, 'big', signed=False)


def to_le_u64(i):
    return i.to_bytes(8, 'little', signed=False)


def write_le_u16(i, out):
    return out.write(to_le_u16(i))


def write_le_u64(i, out):
    return out.write(to_le_u64(i))


def write_chunk(chunk_type, chunk_bytes, out):
    wlen = out.write(chunk_type)
    wlen += write_le_u64(len(chunk_bytes), out)
    wlen += out.write(chunk_bytes)

    hasher = hashlib.sha256()
    hasher.update(chunk_bytes)
    wlen += out.write(hasher.digest())

    return wlen


def write_page_alignment_padding(pos, out):
    return out.write(b'0' * (4096 - pos % 4096))


#def write_chunk(chunk_type, chunk_length, chunk_gen, out):
#    wlen = write_le_u64(chunk_length, out)
#    wlen += out.write(chunk_type)
#
#    hasher = hashlib.sha256()
#    dbeg = wlen;
#    for b in chunk_gen:
#        wlen += out.write(b)
#        hasher.update(b)
#
#    if wlen - dbeg != chunk_length:
#        raise RuntimeError(f"chunk length {chunk_length} != {wlen-dbeg} data length")
#
#    wlen += out.write(hasher.digest())
#
#    return wlen


def write_magic(out):
    return out.write(b'SetOHash')


def write_fhdr(version, hashset_name, hashset_desc, timestamp, out):
    chbuf = io.BytesIO()
    write_le_u64(version, chbuf)
    write_pstring(hashset_name, chbuf)
    write_pstring(timestamp, chbuf)
    write_pstring(hashset_desc, chbuf)

    return write_chunk(b'FHDR', chbuf.getbuffer(), out)


def write_hhnn(hash_type, hash_type_name, hash_length, hash_count, out):
    chbuf = io.BytesIO()
    write_pstring(hash_type_name, chbuf)
    write_le_u64(hash_length, chbuf)
    write_le_u64(hash_count, chbuf)

    return write_chunk(b'HH' + to_be_u16(hash_type), chbuf.getbuffer(), out)


def write_hdat(hashes, out):
    return write_chunk(b'HDAT', b''.join(hashes), out)


def write_ridx(ridx, out):
    return write_chunk(b'RIDX', b''.join(ridx), out)


def write_rdat(records, out):
    rdat = b''.join(field for record in records for field in record)
    return write_chunk(b'RDAT', rdat, out)


def write_rhdr(hash_infos, record_count, out):
    chbuf = io.BytesIO()
    write_le_u64(sum(hi.length for hi in hash_infos), chbuf)
    write_le_u64(record_count, chbuf)

    for hi in hash_infos:
        write_le_u16(hi.type, chbuf)
        write_pstring(hi.name, chbuf)
        write_le_u64(hi.length, chbuf)

    return write_chunk(b'RHDR', chbuf.getbuffer(), out)


def write_ftoc(toc, out):
    chbuf = io.BytesIO()
    for offset, chtype in toc:
        write_le_u64(offset, chbuf)
        chbuf.write(chtype)

    return write_chunk(b'FTOC', chbuf.getbuffer(), out)


def size_to_u64(s):
    return to_le_u64(int(s))


def run(hashset_name, hashset_desc, hash_type_names, inlines, out):
    version = 2

# TODO: types must be unique

    hash_infos = [
        HASH_INFO.get(n, HASH_INFO['other']) for n in hash_type_names
    ]

    conv = [
        bytes.fromhex if i.type != SIZES else size_to_u64 for i in hash_infos
    ]

    records = []

# TODO: deal with missing record fields
    # read the input into records
    for line in nonempty_lines(inlines):
        cols = line.split(' ')
        rec = [conv[i](c) for i, c in enumerate(cols)]
        records.append(rec)

    # set the timestamp
    timestamp = datetime.datetime.now().isoformat(timespec='microseconds')

    toc = []
    pos = 0

    # Magic
    pos += write_magic(out)

    # FHDR
    toc.append((pos, b'FHDR'))
    pos += write_fhdr(version, hashset_name, hashset_desc, timestamp, out)

    for i, hi in enumerate(hash_infos):
        recs = [(r[i], ri) for ri, r in enumerate(records)]
        recs.sort()

        hashes = []
        ridx = []
        for r in recs:
            hashes.append(r[0])
            ridx.append(to_le_u64(r[1]))

        # HHnn
        toc.append((pos, b'HH' + to_be_u16(hi.type)))
        pos += write_hhnn(hi.type, hi.name, hi.length, len(hashes), out)

        # HHNT
        # TODO

        # HDAT
        pos += write_page_alignment_padding(pos, out)
        toc.append((pos, b'HDAT'))
        pos += write_hdat(hashes, out)

        # RIDX
        toc.append((pos, b'RIDX'))
        pos += write_ridx(ridx, out)

    # RHDR
    toc.append((pos, b'RHDR'))
    pos += write_rhdr(hash_infos, len(records), out)

    # RDAT
    toc.append((pos, b'RDAT'))
    pos += write_rdat(records, out)

    # FTOC
    toc.append((pos, b'FTOC'))
    pos += write_ftoc(toc, out)

    print(f'wrote {pos} bytes', file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("hashset_name", help="Name of hash set")
    parser.add_argument("hashset_desc", help="Hash set description")
    parser.add_argument("hash_type", help="Hash type", nargs='*')
    args = parser.parse_args()

    run(
        args.hashset_name,
        args.hashset_desc,
        args.hash_type,
        sys.stdin,
        sys.stdout.buffer
    )
