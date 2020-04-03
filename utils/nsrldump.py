#!/usr/bin/python3

import csv
import io
import sys

# Fun note:
# 
# NSRL files don't have a consistent encoding. While the hash and file size
# columns are ASCII, the filename column is encoded as however the filename
# was encoded (!). For example, the file named
#
#   Gerät, Betriebsmittel, Funktionseinheit, Form 1.StvVar
#
# is listed in the NSRL with the byte E4 for the 'ä', which makes it most
# probably iso_8859-1.
#
# This is would be aggravating if we were trying to extract filenames, but
# fortunately is merely a nuisance when extracting hashes and sizes. Hence,
# we deal with it by specifying ASCII encoding and replacing errors.

instream = io.TextIOWrapper(
    sys.stdin.buffer, encoding='ascii', errors='replace'
)

# first row is the header, skip it
instream.readline()

# dump the SHA-1 and size
reader = csv.reader(instream, delimiter=',', quotechar='"')
for row in reader:
    print(row[0], row[4], file=sys.stdout)
