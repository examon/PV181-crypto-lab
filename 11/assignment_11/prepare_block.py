# Tomas Meszaros - 422336

import hashlib
import sys

if len(sys.argv) != 2:
    print "need file"
    sys.exit(1)

f = open(sys.argv[1], 'r')
txt = f.read()
h = hashlib.new('sha1')
h.update(txt)
digest = h.digest()

template = "\x00\x01%s\x00"
filler = 90*"\xff"
padding = template % filler

digestinfo = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

final = padding + digestinfo + digest
for i in range(len(final)):
    print "{:02x}".format(ord(final[i])),
    if (i + 1) % 16 == 0:
        print

