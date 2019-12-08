#! /usr/bin/python
# by pts@fazekas.hu at Sun Dec  8 14:10:07 CET 2019

"""Cipher test for tinygpgs.

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

if type(zip()) is not list:  # Python 3.
  xrange = range
  try:
    callable
  except NameError:  # Python 3.1.
    def callable(obj):
      return bool(getattr(obj, '__call__', None))

from tinygpgs import cipher as cipher_mod  # Slow ciphers in pure Python.


def test_codebook(codebook, cipher_classname, plaintext, expected_ciphertext_hex):
  ciphertext = codebook.encrypt(plaintext)
  ciphertext_hex = binascii.hexlify(ciphertext)
  if type(ciphertext_hex) != str:  # Python 3.
    ciphertext_hex = str(ciphertext_hex, 'ascii')
  assert ciphertext_hex == expected_ciphertext_hex, [cipher_classname, ciphertext_hex]
  plaintext2 = codebook.decrypt(ciphertext)  # Not used in GPG decryption.
  #plaintext2_hex = binascii.hexlify(plaintext2)
  #if type(plaintext2_hex) != str:  # Python 3.
  #  plaintext2_hex = str(plaintext2_hex, 'ascii')
  assert plaintext2 == plaintext


slow_count_ary, pycrypto_count_ary = [0], [0]


def test_cipher(cipher_classname, block_size, keytable_size, expected_ciphertext_hex):
  slow_count_ary[0] += 1
  cipher_cons = getattr(cipher_mod, cipher_classname, None)
  if not callable(cipher_cons):
    raise ValueError('Cipher not found: tinygpgs.cipher.%s' % cipher_classname)
  keytable = struct.pack('>%dB' % keytable_size, *(b for b in xrange(42, 42 + keytable_size)))
  plaintext = struct.pack('>%dB' % block_size, *(b for b in xrange(137, 137 + block_size)))
  codebook = cipher_cons(keytable)
  test_codebook(codebook, cipher_classname, plaintext, expected_ciphertext_hex)
  cname = 'Crypto.Cipher._' + cipher_classname
  try:
    __import__(cname)
    cipher_cons = getattr(sys.modules[cname], 'new', None)
  except (ImportError, KeyError, AttributeError):
    cipher_cons = None
  if callable(cipher_cons):
    pycrypto_count_ary[0] += 1
    codebook = cipher_cons(keytable)
    test_codebook(codebook, cipher_classname, plaintext, expected_ciphertext_hex)


def test():
  test_cipher('IDEA', 8, 16, '2c08617c243c08ff')  # Doesn't exist in PyCrypto <=2.7.
  test_cipher('CAST', 8, 16, 'fbcb6a621d55fa75')
  test_cipher('AES', 16, 16, 'bbc34d14af57f33220865a796f6d5b34')
  test_cipher('AES', 16, 24, 'c18b3fdd3e336eea6107359d4d706df4')
  test_cipher('AES', 16, 32, '9aaba3033863bd359a61799edd1162a5')
  test_cipher('DES3', 8, 24, 'bd881123d25f4d20')
  test_cipher('DES', 8, 8, '11abb8d810093a25')
  test_cipher('Blowfish', 8, 16, '80e4f5ff4f0ff24d')
  test_cipher('Twofish', 16, 16, 'b9b420b16900d6cc99c827feabcff54d')  # Doesn't exist in PyCrypto <=2.7.
  test_cipher('Twofish', 16, 32, 'bbeab9a4f40a641e752d554897c55107')  # Doesn't exist in PyCrypto <=2.7.


if __name__ == '__main__':
  try:
    try:
      test()
    finally:
      stats_msg = '-'
      stats_msg = 'python=%d.%d slow_count=%d pycrypto_count=%d' % (sys.version_info[0], sys.version_info[1], slow_count_ary[0], pycrypto_count_ary[0])
    sys.stdout.write('%s OK, %s\n' % (__file__, stats_msg))
  except:
    import traceback
    traceback.print_exc()
    sys.stdout.write('%s failed, %s\n' % (__file__, stats_msg))
