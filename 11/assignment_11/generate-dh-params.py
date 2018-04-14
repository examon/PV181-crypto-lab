#!/usr/bin/env python

"""
Author: Tomas Meszaros - 422336

Generate dh parameters and save them to the dhparams.der file.
"""

import subprocess

generate = "openssl dhparam -outform DER -out dhparams.der 2048"
check = "openssl dhparam -inform DER -in dhparams.der -check -text"
print(subprocess.check_output(generate.split()))
print(subprocess.check_output(check.split()))
