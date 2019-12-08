#! /usr/bin/python
# by pts@fazekas.hu at Sun Dec  8 14:10:07 CET 2019

"""Hash test for tinygpgs.

This test works in Python >=2.4 (including Python 3), with or without hashlib.
"""

import binascii
import os
import os.path
import struct
import sys

libdir = os.path.join(os.path.dirname(__file__), 'lib')
pyname = os.path.join(libdir, 'tinygpgs', 'hash.py')
if not os.path.exists(pyname):
  sys.exit('fatal: missing program file: %s\n' % pyname)
sys.path[0] = libdir  # Override script directory.
if sys.version_info[:2] < (2, 6):
  from tinygpgs import f  # Python syntax fixes at import time.

if type(u'') == str:  # Python 3.
  xrange, buffer = range, None
empty_binary = struct.pack('')

from tinygpgs import hash as hash_mod  # Slow hashes in pure Python.


def test_hash_data(hash_obj, hash, data, expected_digest_hex):
  hash_obj.update(data[:13])
  if buffer:
    hash_obj.update(buffer(data, 13))
  else:  # Python 3.
    hash_obj.update(memoryview(data)[13:])
  hash_obj.update(empty_binary)
  digest = hash_obj.digest()
  digest_hex = binascii.hexlify(digest)
  if type(digest_hex) != str:  # Python 3.
    digest_hex = str(digest_hex, 'ascii')
  assert digest_hex == expected_digest_hex, [hash, digest_hex]


slow_count_ary, fast_count_ary = [0], [0]


def test_hash(hash, expected_digest1_hex, expected_digest2_hex=None):
  slow_count_ary[0] += 1
  digest_cons = getattr(hash_mod, 'Slow_' + hash, None)
  if not callable(digest_cons):
    raise ValueError('Hash not found: tinygpgs.hash.%s' % hash)
  # len(data) % 64 == 56 is the usual digest boundary.
  data1 = struct.pack('>%dB' % (64 + 56), *(b & 255 for b in xrange(252, 252 + 64 + 56)))
  hash_obj = digest_cons()
  test_hash_data(hash_obj, hash, data1, expected_digest1_hex)
  if expected_digest2_hex is not None:
    data2 = struct.pack('>%dB' % (128 + 112), *(b & 255 for b in xrange(211, 211 + 128 + 112)))
    hash_obj = digest_cons()
    test_hash_data(hash_obj, hash, data2, expected_digest2_hex)
  try:
    hashlib = __import__('hashlib')
    hashlib.new(hash)
    digest_cons2 = lambda data=empty_binary: hashlib.new(hash, data)
  except (ImportError, ValueError):
    digest_cons2 = None
  if digest_cons2 is None and hash == 'sha1':  # Fallback for Python 2.4.
    try:
      digest_cons2 = __import__('sha').sha
    except (ImportError, AttributeError):
      digest_cons2 = None
  elif digest_cons2 is None and hash == 'md5':  # Fallback for Python 2.4.
    try:
      digest_cons2 = __import__('md5').md5
    except (ImportError, AttributeError):
      digest_cons2 = None
  if callable(digest_cons2):
    fast_count_ary[0] += 1
    hash_obj = digest_cons2()
    test_hash_data(hash_obj, hash, data1, expected_digest1_hex)
    if expected_digest2_hex is None:
      data3 = data1
    else:
      hash_obj = digest_cons2()
      test_hash_data(hash_obj, hash, data2, expected_digest2_hex)
      data3 = data2
    # Check behavior on block boundary.
    assert digest_cons(data3[:-1]).digest() == digest_cons2(data3[:-1]).digest()
    assert digest_cons(data3 + struct.pack('>B', 42)).digest() == digest_cons2(data3 + struct.pack('>B', 42)).digest()


def test():
  test_hash('sha512', 'd09c5c8eda6f99b87275882d0d7c2c1ad3464d14877e9d9078a858043b731c4d111102afa3643b3b6ebb10e558fd7108f21a048f2d0ea61579eba63e088fd082',
            '2735c0403ddde08ff9279f4cfde770207f4657838920eb559192d6f8e389a84046e4877580e6d2ecb34e8b1db39bd04eb5d21962d9f3a34df0fc51a673e76b17')
  test_hash('sha384', '99635e48208f59ee992f727de0c4122f3ac81c3b5bd3afa5f7f7d9f7c3ba832211813b105a2eef3ff3ede279342f2e7c',
            'c51d47e33e28f8f0924d895d64bdd3d6f3043fd06f8862674228b823bd9d1b707ec2e0921b91c1deb2422196a575fb75')
  test_hash('sha256', 'f02f33603f5034151c130e7f169a4d5cc505ac725018ef245f0c22ce1cf3ad98')
  test_hash('sha224', 'ccf49966d67faba703f5a46a5e8a246b74b5a185c6b7e4231dc6f675')
  test_hash('sha1', '6e2a5a4758c25a47fae903e8bb2ca9b7be66f2e3')
  test_hash('ripemd160', '61916ce4720b8cc64247075cfb0ef81b546bfb30')
  test_hash('md5', 'ebb41f12119a58c329b766c7d14fa315')


if __name__ == '__main__':
  try:
    try:
      test()
    finally:
      stats_msg = '-'
      stats_msg = 'python=%d.%d slow_count=%d fast_count=%d' % (sys.version_info[0], sys.version_info[1], slow_count_ary[0], fast_count_ary[0])
    sys.stdout.write('%s OK, %s\n' % (__file__, stats_msg))
  except:
    import traceback
    traceback.print_exc()
    sys.stdout.write('%s failed, %s\n' % (__file__, stats_msg))
