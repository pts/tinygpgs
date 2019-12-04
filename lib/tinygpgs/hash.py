"""Pure Python (slow) implementation of OpenPGP hashes.

Use hashlib for faster implementations.
"""

import itertools
import struct

from tinygpgs.strxor import make_strxor

# --- SHA-512 hash (message digest).


def _sha512_rotr64(x, y):
  return ((x >> y) | (x << (64 - y))) & 0xffffffffffffffff


_sha512_k = (
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817)


def slow_sha512_process(block, hh, _izip=itertools.izip, _rotr64=_sha512_rotr64, _k=_sha512_k):
  w = [0] * 80
  w[:16] = struct.unpack('>16Q', block)
  for i in xrange(16, 80):
    w[i] = (w[i - 16] + (_rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)) + w[i - 7] + (_rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6))) & 0xffffffffffffffff
  a, b, c, d, e, f, g, h = hh
  for i in xrange(80):
    t1 = h + (_rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)) + ((e & f) ^ ((~e) & g)) + _k[i] + w[i]
    t2 = (_rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))
    a, b, c, d, e, f, g, h = (t1 + t2) & 0xffffffffffffffff, a, b, c, (d + t1) & 0xffffffffffffffff, e, f, g
  return [(x + y) & 0xffffffffffffffff for x, y in _izip(hh, (a, b, c, d, e, f, g, h))]


del _sha512_rotr64, _sha512_k  # Unpollute namespace.


# Fallback pure Python implementation of SHA-512 based on
# https://github.com/thomdixon/pysha2/blob/master/sha2/sha512.py
# It is about 400 times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.sha512.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5, install hashlib or pycrypto from PyPi, all of which
# contain a faster SHA-512 implementation in C.
class Slow_sha512(object):
  _h0 = (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
         0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)

  block_size = 128
  digest_size = 64

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf, process = self._buffer, slow_sha512_process
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 128:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 128
        i = 128 - lb
        hh = process(buf + m[:i], hh)
      for i in xrange(i, lm - 127, 128):
        hh = process(_buffer(m, i, 128), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 127):]

  def digest(self):
    c = self._counter
    if (c & 127) < 112:
      return struct.pack('>8Q', *slow_sha512_process(self._buffer + struct.pack('>c%dxQ' % (119 - (c & 127)), '\x80', c << 3), self._h))
    else:
      return struct.pack('>8Q', *slow_sha512_process(struct.pack('>120xQ', c << 3), slow_sha512_process(self._buffer + struct.pack('>c%dx' % (~c & 127), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer, other._counter, other._h = self._buffer, self._counter, self._h
    return other


# --- SHA-384 hash (message digest).


# Fallback pure Python implementation of SHA-384 based on
# https://github.com/thomdixon/pysha2/blob/master/sha2/sha384.py
# It is about 400 times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.new('sha384') using OpenSSL.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5.
class Slow_sha384(Slow_sha512):
  # Overrides Slow_sha512._h0.
  _h0 = (0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
         0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4)

  block_size = 128
  digest_size = 48

  def digest(self):
    return Slow_sha512.digest(self)[:48]


# --- SHA-256 hash (message digest).


def _sha256_rotr32(x, y):
  return ((x >> y) | (x << (32 - y))) & 0xffffffff


_sha256_k = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)


def slow_sha256_process(block, hh, _izip=itertools.izip, _rotr32=_sha256_rotr32, _k=_sha256_k):
  w = [0] * 64
  w[:16] = struct.unpack('>16L', block)
  for i in xrange(16, 64):
    w[i] = (w[i - 16] + (_rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] + (_rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10))) & 0xffffffff
  a, b, c, d, e, f, g, h = hh
  for i in xrange(64):
    t1 = h + (_rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)) + ((e & f) ^ ((~e) & g)) + _k[i] + w[i]
    t2 = (_rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
    a, b, c, d, e, f, g, h = (t1 + t2) & 0xffffffff, a, b, c, (d + t1) & 0xffffffff, e, f, g
  return [(x + y) & 0xffffffff for x, y in _izip(hh, (a, b, c, d, e, f, g, h))]


del _sha256_rotr32, _sha256_k  # Unpollute namespace.


# Fallback pure Python implementation of SHA-256 based on
# https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py
# It is about 400+ times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.sha256.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5, install hashlib or pycrypto from PyPi, all of which
# contain a faster SHA-256 implementation in C.
class Slow_sha256(object):
  _h0 = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

  block_size = 64
  digest_size = 32

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf, process = self._buffer, slow_sha256_process
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 64:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 64
        i = 64 - lb
        hh = process(buf + m[:i], hh)
      for i in xrange(i, lm - 63, 64):
        hh = process(_buffer(m, i, 64), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 63):]

  def digest(self):
    c = self._counter
    if (c & 63) < 56:
      return struct.pack('>8L', *slow_sha256_process(self._buffer + struct.pack('>c%dxQ' % (55 - (c & 63)), '\x80', c << 3), self._h))
    else:
      return struct.pack('>8L', *slow_sha256_process(struct.pack('>56xQ', c << 3), slow_sha256_process(self._buffer + struct.pack('>c%dx' % (~c & 63), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer, other._counter, other._h = self._buffer, self._counter, self._h
    return other


# --- SHA-224 hash (message digest).


# Fallback pure Python implementation of SHA-224 based on
# https://github.com/thomdixon/pysha2/blob/master/sha2/sha224.py
# It is about 400 times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.new('sha224') using OpenSSL.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5.
class Slow_sha224(Slow_sha256):
  # Overrides Slow_sha256._h0.
  _h0 = (0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
         0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4)

  block_size = 64
  digest_size = 28

  def digest(self):
    return Slow_sha256.digest(self)[:28]


# --- SHA-1 hash (message digest).


def _sha1_rotl32(x, y):
  return ((x << y) | (x >> (32 - y))) & 0xffffffff


def slow_sha1_process(block, hh, _izip=itertools.izip, _rotl=_sha1_rotl32):
  w = [0] * 80
  w[:16] = struct.unpack('>16L', block)
  for i in xrange(16, 80):
    w[i] = _rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
  a, b, c, d, e = hh
  for i in xrange(0, 20):
    f = (b & c) | ((~b) & d)
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0x5a827999 + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  for i in xrange(20, 40):
    f = b ^ c ^ d
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0x6ed9eba1 + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  for i in xrange(40, 60):
    f = (b & c) | (b & d) | (c & d)
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0x8f1bbcdc + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  for i in xrange(60, 80):
    f = b ^ c ^ d
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0xca62c1d6 + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  return [(x + y) & 0xffffffff for x, y in _izip(hh, (a, b, c, d, e))]


del _sha1_rotl32  # Unpollute namespace.


# Fallback pure Python implementation of SHA-1 based on
# https://codereview.stackexchange.com/a/37669
# It is about 162 times slower than OpenSSL's C implementation.
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Even Python 2.4 has sha.sha (autodetected below),
# and Python >=2.5 has hashlib.sha1 (also autodetected below), so most
# users don't need this implementation.
class Slow_sha1(object):
  _h0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

  block_size = 64
  digest_size = 20

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf, process = self._buffer, slow_sha1_process
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 64:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 64
        i = 64 - lb
        hh = process(buf + m[:i], hh)
      for i in xrange(i, lm - 63, 64):
        hh = process(_buffer(m, i, 64), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 63):]

  def digest(self):
    c = self._counter
    if (c & 63) < 56:
      return struct.pack('>5L', *slow_sha1_process(self._buffer + struct.pack('>c%dxQ' % (55 - (c & 63)), '\x80', c << 3), self._h))
    else:
      return struct.pack('>5L', *slow_sha1_process(struct.pack('>56xQ', c << 3), slow_sha1_process(self._buffer + struct.pack('>c%dx' % (~c & 63), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer, other._counter, other._h = self._buffer, self._counter, self._h
    return other


# --- RIPEMD-160 hash (message digest).


def _ripemd160_rotl32(x, y):
  x &= 0xffffffff
  return (x << y) | (x >> (32 - y))


def slow_ripemd160_process(
    block, hh, _rotl32=_ripemd160_rotl32,
    _rstu0=((0, 11, 5, 8), (1, 14, 14, 9), (2, 15, 7, 9), (3, 12, 0, 11), (4, 5, 9, 13), (5, 8, 2, 15), (6, 7, 11, 15), (7, 9, 4, 5), (8, 11, 13, 7), (9, 13, 6, 7), (10, 14, 15, 8), (11, 15, 8, 11), (12, 6, 1, 14), (13, 7, 10, 14), (14, 9, 3, 12), (15, 8, 12, 6)),
    _rstu1=((7, 7, 6, 9), (4, 6, 11, 13), (13, 8, 3, 15), (1, 13, 7, 7), (10, 11, 0, 12), (6, 9, 13, 8), (15, 7, 5, 9), (3, 15, 10, 11), (12, 7, 14, 7), (0, 12, 15, 7), (9, 15, 8, 12), (5, 9, 12, 7), (2, 11, 4, 6), (14, 7, 9, 15), (11, 13, 1, 13), (8, 12, 2, 11)),
    _rstu2=((3, 11, 15, 9), (10, 13, 5, 7), (14, 6, 1, 15), (4, 7, 3, 11), (9, 14, 7, 8), (15, 9, 14, 6), (8, 13, 6, 6), (1, 15, 9, 14), (2, 14, 11, 12), (7, 8, 8, 13), (0, 13, 12, 5), (6, 6, 2, 14), (13, 5, 10, 13), (11, 12, 0, 13), (5, 7, 4, 7), (12, 5, 13, 5)),
    _rstu3=((1, 11, 8, 15), (9, 12, 6, 5), (11, 14, 4, 8), (10, 15, 1, 11), (0, 14, 3, 14), (8, 15, 11, 14), (12, 9, 15, 6), (4, 8, 0, 14), (13, 9, 5, 6), (3, 14, 12, 9), (7, 5, 2, 12), (15, 6, 13, 9), (14, 8, 9, 12), (5, 6, 7, 5), (6, 5, 10, 15), (2, 12, 14, 8)),
    _rstu4=((4, 9, 12, 8), (0, 15, 15, 5), (5, 5, 10, 12), (9, 11, 4, 9), (7, 6, 1, 12), (12, 8, 5, 5), (2, 13, 8, 14), (10, 12, 7, 6), (14, 5, 6, 8), (1, 12, 2, 13), (3, 13, 13, 6), (8, 14, 14, 5), (11, 11, 0, 15), (6, 8, 3, 13), (15, 5, 9, 11), (13, 6, 11, 11))):
  x = struct.unpack("<16L", block)
  a, b, c, d, e = f, g, h, i, j = hh
  for r, s, t, u in _rstu0:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + (b ^ c ^ d) + x[r]), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + (g ^ (h | ~i)) + x[t] + 1352829926), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu1:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + ((b & c) | (~b & d)) + x[r] + 1518500249), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + ((g & i) | (h & ~i)) + x[t] + 1548603684), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu2:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + ((b | ~c) ^ d) + x[r] + 1859775393), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + ((g | ~h) ^ i) + x[t] + 1836072691), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu3:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + ((b & d) | (c & ~d)) + x[r] + 2400959708), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + ((g & h) | (~g & i)) + x[t] + 2053994217), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu4:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + (b ^ (c | ~d)) + x[r] + 2840853838), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + (g ^ h ^ i) + x[t]), u) + j, g, _rotl32(h, 10), i
  return (hh[1] + c + i) & 0xffffffff, (hh[2] + d + j) & 0xffffffff, (hh[3] + e + f) & 0xffffffff, (hh[4] + a + g) & 0xffffffff, (hh[0] + b + h) & 0xffffffff


del _ripemd160_rotl32  # Unpollute namespace.


# Fallback pure Python implementation of RIPEMD-160 based on
# https://github.com/dlitz/pycrypto/blob/1660c692982b01741176047eefa53d794f8a81bc/Hash/RIPEMD160.py
# It is about 400+ times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.new('ripemd160') using OpenSSL.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5.
class Slow_ripemd160(object):
  _h0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

  block_size = 64
  digest_size = 20

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf, process = self._buffer, slow_ripemd160_process
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 64:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 64
        i = 64 - lb
        hh = process(buf + m[:i], hh)
      for i in xrange(i, lm - 63, 64):
        hh = process(_buffer(m, i, 64), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 63):]

  def digest(self):
    c = self._counter
    # Merkle-Damgard strengthening, per RFC 1320.
    if (c & 63) < 56:
      return struct.pack('<5L', *slow_ripemd160_process(self._buffer + struct.pack('<c%dxQ' % (55 - (c & 63)), '\x80', c << 3), self._h))
    else:
      return struct.pack('<5L', *slow_ripemd160_process(struct.pack('<56xQ', c << 3), slow_ripemd160_process(self._buffer + struct.pack('<c%dx' % (~c & 63), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer, other._counter, other._h = self._buffer, self._counter, self._h
    return other


# --- MD5 hash (message digest).


def _md5_rotl32(x, n):
  x &= 0xffffffff
  return ((x << n) | (x >> (32 - n)))


def slow_md5_process(block, hh, _md5_rotl32=_md5_rotl32, _unpack=struct.unpack):
  block = _unpack('<16L', block)
  a, b, c, d = hh

  a = _md5_rotl32(a + ((b & c) | (~b & d)) + block[0] + 0xd76aa478, 7) + b
  d = _md5_rotl32(d + ((a & b) | (~a & c)) + block[1] + 0xe8c7b756, 12) + a
  c = _md5_rotl32(c + ((d & a) | (~d & b)) + block[2] + 0x242070db, 17) + d
  b = _md5_rotl32(b + ((c & d) | (~c & a)) + block[3] + 0xc1bdceee, 22) + c
  a = _md5_rotl32(a + ((b & c) | (~b & d)) + block[4] + 0xf57c0faf, 7) + b
  d = _md5_rotl32(d + ((a & b) | (~a & c)) + block[5] + 0x4787c62a, 12) + a
  c = _md5_rotl32(c + ((d & a) | (~d & b)) + block[6] + 0xa8304613, 17) + d
  b = _md5_rotl32(b + ((c & d) | (~c & a)) + block[7] + 0xfd469501, 22) + c
  a = _md5_rotl32(a + ((b & c) | (~b & d)) + block[8] + 0x698098d8, 7) + b
  d = _md5_rotl32(d + ((a & b) | (~a & c)) + block[9] + 0x8b44f7af, 12) + a
  c = _md5_rotl32(c + ((d & a) | (~d & b)) + block[10] + 0xffff5bb1, 17) + d
  b = _md5_rotl32(b + ((c & d) | (~c & a)) + block[11] + 0x895cd7be, 22) + c
  a = _md5_rotl32(a + ((b & c) | (~b & d)) + block[12] + 0x6b901122, 7) + b
  d = _md5_rotl32(d + ((a & b) | (~a & c)) + block[13] + 0xfd987193, 12) + a
  c = _md5_rotl32(c + ((d & a) | (~d & b)) + block[14] + 0xa679438e, 17) + d
  b = _md5_rotl32(b + ((c & d) | (~c & a)) + block[15] + 0x49b40821, 22) + c
  a = _md5_rotl32(a + ((b & d) | (c & ~d)) + block[1] + 0xf61e2562, 5) + b
  d = _md5_rotl32(d + ((a & c) | (b & ~c)) + block[6] + 0xc040b340, 9) + a
  c = _md5_rotl32(c + ((d & b) | (a & ~b)) + block[11] + 0x265e5a51, 14) + d
  b = _md5_rotl32(b + ((c & a) | (d & ~a)) + block[0] + 0xe9b6c7aa, 20) + c
  a = _md5_rotl32(a + ((b & d) | (c & ~d)) + block[5] + 0xd62f105d, 5) + b
  d = _md5_rotl32(d + ((a & c) | (b & ~c)) + block[10] + 0x02441453, 9) + a
  c = _md5_rotl32(c + ((d & b) | (a & ~b)) + block[15] + 0xd8a1e681, 14) + d
  b = _md5_rotl32(b + ((c & a) | (d & ~a)) + block[4] + 0xe7d3fbc8, 20) + c
  a = _md5_rotl32(a + ((b & d) | (c & ~d)) + block[9] + 0x21e1cde6, 5) + b
  d = _md5_rotl32(d + ((a & c) | (b & ~c)) + block[14] + 0xc33707d6, 9) + a
  c = _md5_rotl32(c + ((d & b) | (a & ~b)) + block[3] + 0xf4d50d87, 14) + d
  b = _md5_rotl32(b + ((c & a) | (d & ~a)) + block[8] + 0x455a14ed, 20) + c
  a = _md5_rotl32(a + ((b & d) | (c & ~d)) + block[13] + 0xa9e3e905, 5) + b
  d = _md5_rotl32(d + ((a & c) | (b & ~c)) + block[2] + 0xfcefa3f8, 9) + a
  c = _md5_rotl32(c + ((d & b) | (a & ~b)) + block[7] + 0x676f02d9, 14) + d
  b = _md5_rotl32(b + ((c & a) | (d & ~a)) + block[12] + 0x8d2a4c8a, 20) + c
  a = _md5_rotl32(a + (b ^ c ^ d) + block[5] + 0xfffa3942, 4) + b
  d = _md5_rotl32(d + (a ^ b ^ c) + block[8] + 0x8771f681, 11) + a
  c = _md5_rotl32(c + (d ^ a ^ b) + block[11] + 0x6d9d6122, 16) + d
  b = _md5_rotl32(b + (c ^ d ^ a) + block[14] + 0xfde5380c, 23) + c
  a = _md5_rotl32(a + (b ^ c ^ d) + block[1] + 0xa4beea44, 4) + b
  d = _md5_rotl32(d + (a ^ b ^ c) + block[4] + 0x4bdecfa9, 11) + a
  c = _md5_rotl32(c + (d ^ a ^ b) + block[7] + 0xf6bb4b60, 16) + d
  b = _md5_rotl32(b + (c ^ d ^ a) + block[10] + 0xbebfbc70, 23) + c
  a = _md5_rotl32(a + (b ^ c ^ d) + block[13] + 0x289b7ec6, 4) + b
  d = _md5_rotl32(d + (a ^ b ^ c) + block[0] + 0xeaa127fa, 11) + a
  c = _md5_rotl32(c + (d ^ a ^ b) + block[3] + 0xd4ef3085, 16) + d
  b = _md5_rotl32(b + (c ^ d ^ a) + block[6] + 0x04881d05, 23) + c
  a = _md5_rotl32(a + (b ^ c ^ d) + block[9] + 0xd9d4d039, 4) + b
  d = _md5_rotl32(d + (a ^ b ^ c) + block[12] + 0xe6db99e5, 11) + a
  c = _md5_rotl32(c + (d ^ a ^ b) + block[15] + 0x1fa27cf8, 16) + d
  b = _md5_rotl32(b + (c ^ d ^ a) + block[2] + 0xc4ac5665, 23) + c
  a = _md5_rotl32(a + (c ^ (b | ~d)) + block[0] + 0xf4292244, 6) + b
  d = _md5_rotl32(d + (b ^ (a | ~c)) + block[7] + 0x432aff97, 10) + a
  c = _md5_rotl32(c + (a ^ (d | ~b)) + block[14] + 0xab9423a7, 15) + d
  b = _md5_rotl32(b + (d ^ (c | ~a)) + block[5] + 0xfc93a039, 21) + c
  a = _md5_rotl32(a + (c ^ (b | ~d)) + block[12] + 0x655b59c3, 6) + b
  d = _md5_rotl32(d + (b ^ (a | ~c)) + block[3] + 0x8f0ccc92, 10) + a
  c = _md5_rotl32(c + (a ^ (d | ~b)) + block[10] + 0xffeff47d, 15) + d
  b = _md5_rotl32(b + (d ^ (c | ~a)) + block[1] + 0x85845dd1, 21) + c
  a = _md5_rotl32(a + (c ^ (b | ~d)) + block[8] + 0x6fa87e4f, 6) + b
  d = _md5_rotl32(d + (b ^ (a | ~c)) + block[15] + 0xfe2ce6e0, 10) + a
  c = _md5_rotl32(c + (a ^ (d | ~b)) + block[6] + 0xa3014314, 15) + d
  b = _md5_rotl32(b + (d ^ (c | ~a)) + block[13] + 0x4e0811a1, 21) + c
  a = _md5_rotl32(a + (c ^ (b | ~d)) + block[4] + 0xf7537e82, 6) + b
  d = _md5_rotl32(d + (b ^ (a | ~c)) + block[11] + 0xbd3af235, 10) + a
  c = _md5_rotl32(c + (a ^ (d | ~b)) + block[2] + 0x2ad7d2bb, 15) + d
  b = _md5_rotl32(b + (d ^ (c | ~a)) + block[9] + 0xeb86d391, 21) + c

  return (hh[0] + a) & 0xffffffff, (hh[1] + b) & 0xffffffff, (hh[2] + c) & 0xffffffff, (hh[3] + d) & 0xffffffff


del _md5_rotl32


# Fallback pure Python implementation of MD5 based on
# https://github.com/doegox/python-cryptoplus/blob/master/src/CryptoPlus/Hash/pymd5.py
# It is about 400+ times slower than OpenSSL's C implementation.
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Even Python 2.4 has md5.md5 (autodetected below),
# and Python >=2.5 has hashlib.md5 (also autodetected below), so most
# users don't need this implementation.
class Slow_md5(object):
  _h0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

  block_size = 64
  digest_size = 16

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf, process = self._buffer, slow_md5_process
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 64:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 64
        i = 64 - lb
        hh = process(buf + m[:i], hh)
      for i in xrange(i, lm - 63, 64):
        hh = process(_buffer(m, i, 64), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 63):]

  def digest(self):
    c = self._counter
    if (c & 63) < 56:
      return struct.pack('<4L', *slow_md5_process(self._buffer + struct.pack('<c%dxQ' % (55 - (c & 63)), '\x80', c << 3), self._h))
    else:
      return struct.pack('<4L', *slow_md5_process(struct.pack('<56xQ', c << 3), slow_md5_process(self._buffer + struct.pack('<c%dx' % (~c & 63), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer, other._counter, other._h = self._buffer, self._counter, self._h
    return other
