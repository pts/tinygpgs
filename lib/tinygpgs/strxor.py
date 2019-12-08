"""Uses the fastest strxor implementation."""

import sys

try:
  __import__('Crypto.Util.strxor')
  fast_strxor = sys.modules['Crypto.Util.strxor'].strxor
  def make_strxor(size, _fast_strxor=fast_strxor):
    return _fast_strxor
except ImportError:
  import itertools
  import struct
  fast_strxor = None
  if type(b'') == str:  # Python 2.
    try:
      bytearray  # Introduced in Python 2.6. Raises NameError in older Python.
      # This is about 26.18% faster than the one below using pack.
      #
      # Using array.array('B', ...) would be a bit slower than using pack.
      def make_strxor(size):
        def strxor(a, b, izip=itertools.izip, ba=bytearray, st=str):
          return st(ba((a ^ b for a, b in izip(ba(a), ba(b)))))
        return strxor
    except NameError:
      # This is the naive implementation in Python 2, it's too slow:
      #
      # def strxor(a, b, izip=itertools.izip):
      #   return ''.join(chr(ord(x) ^ ord(y)) for x, y in izip(a, b))
      #
      # 58 times slower pure Python implementation, see
      # http://stackoverflow.com/a/19512514/97248
      def make_strxor(size):
        def strxor(a, b, izip=itertools.izip, pack=struct.pack, unpack=struct.unpack, fmt='%dB' % size):
          return pack(fmt, *(a ^ b for a, b in izip(unpack(fmt, a), unpack(fmt, b))))
        return strxor
  else:
    def make_strxor(size):
      def strxor(a, b, _zip=zip, _bytes=bytes):
        return _bytes((a ^ b for a, b in _zip(a, b)))
      return strxor
