#!/usr/bin/env python2

import subprocess
import sys

if len(sys.argv) != 2:
    print "need private key as agrument"
    sys.exit(1)
cmd = "openssl rsa -text -noout -inform DRA -in"
keyinfo = subprocess.check_output(cmd.split() + [sys.argv[1]])
for item in keyinfo.split('\n'):
    if item.startswith("publicExponent"):
        print item
