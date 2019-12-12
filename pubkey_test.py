#! /usr/bin/python
# by pts@fazekas.hu at Sun Dec 15 16:54:36 CET 2019

"""Public-key cryptography test for tinygpgs.

This test works in Python >=2.4 (including Python 3), with or without PyCrypto.
"""

import binascii
import os
import os.path
import struct
import sys

libdir = os.path.join(os.path.dirname(__file__), 'lib')
pyname = os.path.join(libdir, 'tinygpgs', 'cipher.py')
if not os.path.exists(pyname):
  sys.exit('fatal: missing program file: %s\n' % pyname)
sys.path[0] = libdir  # Override script directory.
if sys.version_info[:2] < (2, 6):
  from tinygpgs import f  # Python syntax fixes at import time.

from tinygpgs import pubkey


def test_curve25519_donna_scalarmult_int():
  scalarmult = pubkey.curve25519_donna_scalarmult_int

  # Test vector is from tinyssh source code:
  # crypto-tests/crypto_scalarmult_curve25519test.c
  basepoint = 9
  d = 0xbfd5696705f113f7421712803857db7d30b1d435584937bd2981b2fdb51e2c56
  r = 0x7fff98b1c8d0b2dd129ec248c3c8f21e5dfd7a37ecaed052b2804c10c2dac3f9
  assert scalarmult(d, basepoint) == r
  assert scalarmult(d) == r
  assert scalarmult(basepoint, d) != r  # Not commutative.

  # Diffie--Hellman key exchange.
  ask, bsk =  int('cd' * 31 + 'ab', 16), int('34' * 31 + '12', 16)
  apk, bpk = scalarmult(ask), scalarmult(bsk)
  assert apk != bpk
  assert scalarmult(ask, bpk) == scalarmult(bsk, apk)
  assert scalarmult(ask, bpk) != scalarmult(bsk, apk ^ 1)


def test_aes_key_wrap():
  # Test vector from https://tools.ietf.org/html/rfc3394
  assert (binascii.hexlify(pubkey.aes_key_wrap(binascii.unhexlify(b'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'), binascii.unhexlify(b'00112233445566778899AABBCCDDEEFF'))) ==
          b'64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7')


def test():
  test_curve25519_donna_scalarmult_int()
  test_aes_key_wrap()


if __name__ == '__main__':
  test()
  sys.stdout.write('%s OK.\n' % __file__)
