#!/usr/bin/python3

# find | xargs sha1sum | cut -f1 -d' ' | sort -u | ./mkhashset.py SHA1 'Some test hashes' >sha1.hset
# for i in NSRLFile.*.txt.gz ; do zcat $i | awk -F',' '{print $1}' | tail -n +2 ; done | cut -b 2-41 | ./mkhashset.py SHA1 'NSRL' >nsrl.hset


import hashlib
import sys

version = 1
flags = 0

hash_type = sys.argv[1]
hashset_name = sys.argv[2]

hashset_desc = "TEST!"

def nonempty_lines(src):
    for line in src:
        line = line.strip()
        if line:
            yield line

hashes = [bytes.fromhex(line) for line in nonempty_lines(sys.stdin)]
hash_length = len(hashes[0])

def expected_index(h, set_size):
    high32 = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]
    return (high32 * set_size) >> 32

max_delta = 0
for i, h in enumerate(hashes):
    ei = expected_index(h, len(hashes))
    max_delta = max(max_delta, abs(i - ei)) 

hashset = b''.join(hashes)
hasher = hashlib.sha256()
hasher.update(hashset)

pos = 0
pos += sys.stdout.buffer.write(b'SetOHash')
pos += sys.stdout.buffer.write(version.to_bytes(8, 'little', signed=False))
pos += sys.stdout.buffer.write(hash_type.encode('UTF-8'))
pos += sys.stdout.buffer.write(b'\0')
pos += sys.stdout.buffer.write(hash_length.to_bytes(8, 'little', signed=False))
pos += sys.stdout.buffer.write(flags.to_bytes(8, 'little', signed=False))
pos += sys.stdout.buffer.write(hashset_name.encode('UTF-8'))
pos += sys.stdout.buffer.write(b'\0')
pos += sys.stdout.buffer.write(len(hashes).to_bytes(8, 'little', signed=False))
pos += sys.stdout.buffer.write(max_delta.to_bytes(8, 'little', signed=False))
pos += sys.stdout.buffer.write(hashset_desc.encode('UTF-8'))
pos += sys.stdout.buffer.write(b'\0')
pos += sys.stdout.buffer.write(hasher.digest())
pos += sys.stdout.buffer.write(b'\0' * (4096-pos))
pos += sys.stdout.buffer.write(hashset)
