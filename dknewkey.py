#!/usr/bin/python
# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2016 Google, Inc.
# Contact: Brandon Long <blong@google.com>
# Modified by Scott Kitterman <scott@kitterman.com>
# Copyright (c) 2017 Scott Kitterman

"""Generates new domainkeys pairs.

"""


import os
import subprocess
import sys
import tempfile
import argparse

# how strong are our keys?
BITS_REQUIRED = 2048

# limit to rsa-sha256?
HTAG='sha256'

# what openssl binary do we use to do key manipulation?
OPENSSL_BINARY = '/usr/bin/openssl'

def GenKeys(private_key_file):
  """ Generates a suitable private key.  Output is unprotected.
  You should encrypt your keys.
  """
  print >> sys.stderr, 'generating ' + private_key_file
  subprocess.check_call([OPENSSL_BINARY, 'genrsa', '-out', private_key_file,
                         str(BITS_REQUIRED)])


def ExtractDnsPublicKey(private_key_file, dns_file, key_type='rsa'):
  """ Given a key, extract the bit we should place in DNS.
  """
  print >> sys.stderr, 'extracting ' + private_key_file
  working_file = tempfile.NamedTemporaryFile(delete=False).name
  subprocess.check_call([OPENSSL_BINARY, 'rsa', '-in', private_key_file,
                         '-out', working_file, '-pubout', '-outform', 'PEM'])
  cmd = 'grep -v ^-- %s | tr -d \'\\n\'' % working_file
  try:
    output = subprocess.check_output(cmd, shell=True)
  finally:
    os.unlink(working_file)
  dns_fp = open(dns_file, "w+")
  print >> sys.stderr, 'writing ' + dns_file
  if HTAG:
      print >> dns_fp, "k={0} h={1}; p={2}".format(key_type,HTAG,output)
  else:
      print >> dns_fp, "k={0}; p={1}".format(key_type, output)
  dns_fp.close()


def main(argv):
  parser = argparse.ArgumentParser(
    description='Produce DKIM keys.',)
  parser.add_argument('key_name', action="store")
  parser.add_argument('--ktype', choices=['rsa', 'rsafp'],
    default='rsa',
    help='DKIM key type: Default is rsa')
  args=parser.parse_args()
  if sys.version_info[0] >= 3:
    args.key_name = bytes(args.key_name, encoding='UTF-8')
    args.ktype = bytes(args.ktype, encoding='UTF-8')
    # Make sys.stdin and stdout binary streams.
    sys.stdin = sys.stdin.detach()
    sys.stdout = sys.stdout.detach()

  key_name = args.key_name
  key_type = args.ktype
  private_key_file = key_name + '.key'
  dns_file = key_name + '.dns'

  GenKeys(private_key_file)
  ExtractDnsPublicKey(private_key_file, dns_file, key_type)


if __name__ == '__main__':
  main(sys.argv)
