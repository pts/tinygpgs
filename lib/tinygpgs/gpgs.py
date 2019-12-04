# by pts@fazekas.hu at Thu Nov 28 22:09:47 CET 2019

"""GPG-compatible symmetric key encryption and decryption code.

Imports PyCrypto.Cipher._* or tinygpgs.cipher lazily.

Imports hashlib or tinygpgs.hash lazily.
"""

import struct
import sys

from tinygpgs.strxor import make_strxor, fast_strxor


def new_hash(hash, data='', is_slow_hash=False, _slow_hashes={}):
  hash = hash.replace('-', '').lower()
  if not is_slow_hash:
    try:
      import hashlib  # Python >= 2.5.
      return hashlib.new(hash, data)
    except (ImportError, ValueError):
      pass
    # .upper() happens to work for SLOW_HASHES.keys().
    module_name = 'Crypto.Hash._' + hash.upper()
    try:
      __import__(module_name)
      digest_cons = sys.modules[module_name].new
    except (ImportError, AttributeError):
      digest_cons = None
    if callable(digest_cons):
      return digest_cons(data)
    if hash == 'sha1':
      try:  # Python 2.4.
        import sha
        return sha.sha(data)
      except ImportError:
        return SlowSha1(data)
    if hash == 'md5':
      try:  # Python 2.4.
        import md5
        return md5.md5(data)
      except ImportError:
        pass
  if not _slow_hashes:
    try:  # Lazy import of tinygpgs.hash makes startup with PyCrypto fast.
      from tinygpgs import hash as hash_mod
      _slow_hashes.update(hash_mod.__dict__)
    except ImportError:
      _slow_hashes[0] = 0  # Not empty.
  digest_cons = _slow_hashes.get('Slow_' + hash)
  if callable(digest_cons):
    return digest_cons(data)
  raise ValueError('Unsupported hash: %s' % hash)  # Never happens.


class BadCfbCipher(ValueError):
  """Raised when a cipher cannot be created in CFB mode."""


# {name: (module_name, block_size, keytable_size)}.
CIPHER_INFOS = {
    'idea': ('IDEA', 8, 16),  # Doesn't exist in PyCrypto <=2.7.
    'cast5': ('CAST', 8, 16),
    'cast5-128': ('CAST', 8, 16),
    'cast128': ('CAST', 8, 16),
    'aes-128': ('AES', 16, 16),
    'aes-192': ('AES', 16, 24),
    'aes-256': ('AES', 16, 32),
    'des3': ('DES3', 8, 24),
    '3des': ('DES3', 8, 24),
    'des': ('DES', 8, 8),
    'blowfish': ('Blowfish', 8, 16),
    'twofish-128': ('Twofish', 16, 16),  # Doesn't exist in PyCrypto <=2.7.
    'twofish-256': ('Twofish', 16, 32),  # Doesn't exist in PyCrypto <=2.7.
}


def get_cipher_cons(cipher, is_slow_cipher, is_cfb, _slow_ciphers={}):
  """Returns (cons, block_size)."""
  cipher = cipher.lower()
  info = CIPHER_INFOS.get(cipher)
  if not info:
    raise ValueError('Unknown cipher: %s' % cipher)
  module_name, block_size, keytable_size = info
  if is_slow_cipher and is_cfb:
    raise BadCfbCipher('Slow cipher %s does not support CFB.' % cipher)
  if not is_slow_cipher:
    cname = 'Crypto.Cipher._' + module_name
    cons = None
    try:
      __import__(cname)
      cons = getattr(sys.modules[cname], 'new', None)
    except ImportError:
      pass
    if callable(cons):  # Fast, C extension.
      return cons, block_size, keytable_size
    if cipher == 'aes':  # Fallback fast C, extension.
      cons2 = None
      try:
        cons2 = getattr(__import__('aes'), 'Keysetup', None)
      except ImportError:  # https://pypi.org/project/alo-aes/
        cons2 = None
      if callable(cons2):
        cons = cons2
  if not _slow_ciphers:
    try:  # Lazy import of tinygpgs.cipher makes startup with PyCrypto fast.
      from tinygpgs import cipher as cipher_mod
      _slow_ciphers.update(cipher_mod.__dict__)
    except ImportError:
      _slow_ciphers[0] = 0  # Not empty.
  fallback_cons = _slow_ciphers.get(module_name)
  if callable(fallback_cons):
    if is_cfb:
      raise BadCfbCipher('Fallback cipher %s does not support CFB.' % cipher)
    return fallback_cons, block_size, keytable_size
  raise ValueError('Unimplemented cipher: %s' % cipher)  # Never happens.


# --- GPG misc: used for both encryption and decryption.


CRC24_TABLE = (
    0x000000, 0x864cfb, 0x8ad50d, 0x0c99f6, 0x93e6e1, 0x15aa1a, 0x1933ec,
    0x9f7f17, 0xa18139, 0x27cdc2, 0x2b5434, 0xad18cf, 0x3267d8, 0xb42b23,
    0xb8b2d5, 0x3efe2e, 0xc54e89, 0x430272, 0x4f9b84, 0xc9d77f, 0x56a868,
    0xd0e493, 0xdc7d65, 0x5a319e, 0x64cfb0, 0xe2834b, 0xee1abd, 0x685646,
    0xf72951, 0x7165aa, 0x7dfc5c, 0xfbb0a7, 0x0cd1e9, 0x8a9d12, 0x8604e4,
    0x00481f, 0x9f3708, 0x197bf3, 0x15e205, 0x93aefe, 0xad50d0, 0x2b1c2b,
    0x2785dd, 0xa1c926, 0x3eb631, 0xb8faca, 0xb4633c, 0x322fc7, 0xc99f60,
    0x4fd39b, 0x434a6d, 0xc50696, 0x5a7981, 0xdc357a, 0xd0ac8c, 0x56e077,
    0x681e59, 0xee52a2, 0xe2cb54, 0x6487af, 0xfbf8b8, 0x7db443, 0x712db5,
    0xf7614e, 0x19a3d2, 0x9fef29, 0x9376df, 0x153a24, 0x8a4533, 0x0c09c8,
    0x00903e, 0x86dcc5, 0xb822eb, 0x3e6e10, 0x32f7e6, 0xb4bb1d, 0x2bc40a,
    0xad88f1, 0xa11107, 0x275dfc, 0xdced5b, 0x5aa1a0, 0x563856, 0xd074ad,
    0x4f0bba, 0xc94741, 0xc5deb7, 0x43924c, 0x7d6c62, 0xfb2099, 0xf7b96f,
    0x71f594, 0xee8a83, 0x68c678, 0x645f8e, 0xe21375, 0x15723b, 0x933ec0,
    0x9fa736, 0x19ebcd, 0x8694da, 0x00d821, 0x0c41d7, 0x8a0d2c, 0xb4f302,
    0x32bff9, 0x3e260f, 0xb86af4, 0x2715e3, 0xa15918, 0xadc0ee, 0x2b8c15,
    0xd03cb2, 0x567049, 0x5ae9bf, 0xdca544, 0x43da53, 0xc596a8, 0xc90f5e,
    0x4f43a5, 0x71bd8b, 0xf7f170, 0xfb6886, 0x7d247d, 0xe25b6a, 0x641791,
    0x688e67, 0xeec29c, 0x3347a4, 0xb50b5f, 0xb992a9, 0x3fde52, 0xa0a145,
    0x26edbe, 0x2a7448, 0xac38b3, 0x92c69d, 0x148a66, 0x181390, 0x9e5f6b,
    0x01207c, 0x876c87, 0x8bf571, 0x0db98a, 0xf6092d, 0x7045d6, 0x7cdc20,
    0xfa90db, 0x65efcc, 0xe3a337, 0xef3ac1, 0x69763a, 0x578814, 0xd1c4ef,
    0xdd5d19, 0x5b11e2, 0xc46ef5, 0x42220e, 0x4ebbf8, 0xc8f703, 0x3f964d,
    0xb9dab6, 0xb54340, 0x330fbb, 0xac70ac, 0x2a3c57, 0x26a5a1, 0xa0e95a,
    0x9e1774, 0x185b8f, 0x14c279, 0x928e82, 0x0df195, 0x8bbd6e, 0x872498,
    0x016863, 0xfad8c4, 0x7c943f, 0x700dc9, 0xf64132, 0x693e25, 0xef72de,
    0xe3eb28, 0x65a7d3, 0x5b59fd, 0xdd1506, 0xd18cf0, 0x57c00b, 0xc8bf1c,
    0x4ef3e7, 0x426a11, 0xc426ea, 0x2ae476, 0xaca88d, 0xa0317b, 0x267d80,
    0xb90297, 0x3f4e6c, 0x33d79a, 0xb59b61, 0x8b654f, 0x0d29b4, 0x01b042,
    0x87fcb9, 0x1883ae, 0x9ecf55, 0x9256a3, 0x141a58, 0xefaaff, 0x69e604,
    0x657ff2, 0xe33309, 0x7c4c1e, 0xfa00e5, 0xf69913, 0x70d5e8, 0x4e2bc6,
    0xc8673d, 0xc4fecb, 0x42b230, 0xddcd27, 0x5b81dc, 0x57182a, 0xd154d1,
    0x26359f, 0xa07964, 0xace092, 0x2aac69, 0xb5d37e, 0x339f85, 0x3f0673,
    0xb94a88, 0x87b4a6, 0x01f85d, 0x0d61ab, 0x8b2d50, 0x145247, 0x921ebc,
    0x9e874a, 0x18cbb1, 0xe37b16, 0x6537ed, 0x69ae1b, 0xefe2e0, 0x709df7,
    0xf6d10c, 0xfa48fa, 0x7c0401, 0x42fa2f, 0xc4b6d4, 0xc82f22, 0x4e63d9,
    0xd11cce, 0x575035, 0x5bc9c3, 0xdd8538,
)


def crc24(data, crc=0xb704ce):
  if not isinstance(data, (str, buffer)):
    raise TypeError
  table = CRC24_TABLE
  for c in data:
    crc = (table[((crc >> 16) ^ ord(c)) & 0xff] ^ (crc << 8)) & 0x00ffffff
  return crc


def str_to_fread(data):
  if not isinstance(data, (str, buffer)):
    raise TypeError
  i_ary = [0]

  def fread_from_str(size):
    i = i_ary[0]
    result = data[i : i + size]
    i_ary[0] = i + len(result)
    return result

  return fread_from_str


# GPG defaults: https://en.wikipedia.org/wiki/GNU_Privacy_Guard says that
# CAST5 has been the default in GPG <2.1 (confirmed for 1.0.6 in
# 2001-06-01). In 2.1, AES-128 became the default. In 2.2, AES-256 became
# the default (confirmed for 2.2.17 in 2019-07-09).
CIPHER_ALGOS = {  # --cipher-algo=... .
    #0: 'unencrypted',  # gpg(1) can't decrypt it either.
    1: 'idea',
    2: '3des',  # With 192-bit key.
    3: 'cast5',  # With 128-bit key.
    4: 'blowfish',  # With 128-bit key, 16 rounds.
    7: 'aes-128',
    8: 'aes-192',
    9: 'aes-256',
    10: 'twofish-256',
    302: 'des',  # Single-key, 56-bit (64-bit?) DES.
    303: 'twofish-128',
}


# https://github.com/gpg/libgcrypt/blob/e5c4cf0efb8fd297963e6b4392ab98c41dbad536/src/gcrypt.h.in#L919
CIPHER_ALGOS_ALL = {
    0: 'unencrypted',  # gpg(1) can't decrypt it either.
    1: 'idea',
    2: '3des',  # With 192-bit key.
    3: 'cast5',  # With 128-bit key.
    4: 'blowfish',  # With 128-bit key, 16 rounds.
    5: 'safer-sk128',
    6: 'des-sk',
    7: 'aes-128',
    8: 'aes-192',
    9: 'aes-256',
    10: 'twofish-256',
    301: 'rc4',  # 'arcfour'.
    302: 'des',  # Single-key, 56-bit (64-bit?) DES.
    303: 'twofish-128',
    304: 'serpent-128',
    305: 'serpent-192',
    306: 'serpent-256',
    307: 'rfc2268-ron-40',
    308: 'rfc2268-ron-128',
    309: 'rfc4269-seed',
    310: 'camellia-128',
    311: 'camellia-192',
    312: 'camellia-256',
    313: 'salsa20',
    314: 'salsa20-r12',
    315: 'rfc-5830-gost',  # GOST 28147-89.
    316: 'chacha20',
}

KEYTABLE_SIZES = dict((_k, CIPHER_INFOS[_v][2]) for _k, _v in CIPHER_ALGOS.iteritems())

DIGEST_ALGOS = {  # --digest-algo=..., --s2k-digest-algo=... .
    1: 'md5',
    2: 'sha1',
    3: 'ripemd160',
    8: 'sha256',
    9: 'sha384',
    10: 'sha512',
    11: 'sha224',
}

S2K_MODES = {
    0: 'simple',
    1: 'salted',
    3: 'iterated-salted',
}

COMPRESS_ALGOS = {
    0: 'uncompressed',
    1: 'zip',
    2: 'zlib',
    3: 'bzip2',
}


def iter_to_fread(iter_str):
  _buffer = buffer
  data_ary, iter_str = [_buffer('')], iter(iter_str)

  def fread_from_iter(size):
    data = data_ary[0]
    if isinstance(size, tuple):  # ``Give me whatever you have buffered''.
      min_size, mod = size
      ld = len(data)
      ldm = ld - ld % mod
      if ldm < min_size:
        return ''
      result, data_ary[0] = _buffer(data, 0, ldm), _buffer(data, ldm)
      return result
    if size <= 0:
      return ''
    result, data = data[:size], _buffer(data, size)
    if len(result) < size:
      remaining = size - len(result)
      result = [result]
      while remaining > 0:
        try:
          data = _buffer(iter_str.next())
        except StopIteration:
          break
        # This may be a long copy, but there is no way around it.
        result.append(data[:remaining])
        data = _buffer(data, len(result[-1]))
        remaining -= len(result[-1])
      result = ''.join(result)
    data_ary[0] = data
    return result

  return fread_from_iter


def iter_to_fread_or_all(iter_str):
  _buffer = buffer
  data_ary, iter_str = [_buffer('')], iter(iter_str)

  def fread_from_iter(size=()):
    data = data_ary[0]
    if size is ():  # Read everything until EOF.
      result, data_ary[0], data = [data[:]], '', ''
      while 1:
        try:
          # This may be a long copy, but there is no way around it.
          result.append(iter_str.next()[:])
        except StopIteration:
          break
        result.append(data)
      return ''.join(result)
    if size <= 0:
      return ''
    result, data = data[:size], _buffer(data, size)
    if len(result) < size:
      remaining = size - len(result)
      result = [result]
      while remaining > 0:
        try:
          data = _buffer(iter_str.next())
        except StopIteration:
          break
        # This may be a long copy, but there is no way around it.
        result.append(data[:remaining])
        data = _buffer(data, len(result[-1]))
        remaining -= len(result[-1])
      result = ''.join(result)
    data_ary[0] = data
    return result

  return fread_from_iter


def get_gpg_cipher(cipher_algo, keytable, is_slow_cipher, cfb_iv=None):
  """Returns (codebook, block_size)."""
  if cipher_algo not in CIPHER_ALGOS:
    raise ValueError('Unsupported cipher_algo: %d' % cipher_algo)
  if KEYTABLE_SIZES[cipher_algo] != len(keytable):
    raise ValueError('Session key must be %d bytes for cipher_algo %s, got: %d' %
                     (KEYTABLE_SIZES[cipher_algo], CIPHER_ALGOS[cipher_algo], len(keytable)))
  cipher_cons, block_size, ks = get_cipher_cons(CIPHER_ALGOS[cipher_algo], is_slow_cipher, cfb_iv)
  assert len(keytable) == ks
  if cfb_iv:
    MODE_CFB = 3  # PyCrypto.
    try:
      return cipher_cons(keytable, MODE_CFB, cfb_iv, segment_size=(block_size << 3)), block_size
    except (TypeError, ValueError), e:  # Example: All slow ciphers (is_slow_cipher).
      raise BadCfbCipher(str(e))
  return cipher_cons(keytable), block_size


def get_gpg_s2k_string_to_key(keytable_size, salt, count, digest_func, passphrase):  # Slow.
  # Calculate session key.
  # https://github.com/mitchellrj/python-pgp/blob/master/pgp/s2k.py
  session_key = []
  session_key_remaining = keytable_size
  sp = salt + passphrase
  del passphrase
  if count <= len(sp):
    count = len(sp)
  while session_key_remaining > 0:
    d, c = digest_func('\0' * len(session_key)), count
    if c >> 16:  # <FAST-HASH>: run little Python code only.
      cx = (1 << 16) // len(sp)
      spx = sp * cx  # At most 64 KiB of memory use.
      while c >= len(spx):
        d.update(spx)
        c -= len(spx)
      assert not c >> 16
    d.update(sp * (c // len(sp)))  # At most 64 KiB.
    d.update(sp[:c % len(sp)])
    session_key.append(d.digest())
    session_key_remaining -= len(session_key[-1])
  session_key = ''.join(session_key)[:keytable_size]
  assert len(session_key) == keytable_size
  return session_key


class _DummyClass(object):
  def dummy():
    pass


def is_python_function(func, _types=(type(_DummyClass().dummy), type(lambda: 0))):
  return type(func) in _types


# --- GPG decryption.


def yield_gpg_binary_packets(fread, c0=''):
  while 1:
    if not c0:
      c0 = fread(1)
    if not c0:
      break
    b, c0 = ord(c0), ''
    if not b & 128:
      raise ValueError('Tag bit 7 expected.')
    if b & 64:  # New-format packet.
      packet_type = b & 63
      if packet_type == 0:
        raise ValueError('Packet type must not be 0.')
      c = fread(1)
      if not c:
        raise ValueError('EOF in new packet size byte 0.')
      b = ord(c)
      if 224 + 9 <= b < 255:
        while 1:
          remaining, is_partial = 1 << (b & 31), True
          while remaining > 0:
            # !! Tune this, allow e.g. 65536 if configured.
            size = min(remaining, 8192)  # Avoid large partial packets.
            data = fread(size)
            if len(data) != size:
              raise ValueError('EOF in partial packet.')
            yield packet_type, is_partial, data
            remaining -= size
          c = fread(1)
          if not c:
            raise ValueError('EOF in after-partial size byte 0.')
          b = ord(c)
          if not 224 <= b < 255:
            break
      if b < 191:
        size = b
      elif b < 224:
        c = fread(1)
        if not c:
          raise ValueError('EOF in new packet size byte 1.')
        size = ((b - 192) << 8 | ord(c)) + 192
      elif b < 255:
        # >= 512 bytes needed.
        raise ValueError('First partial body too short.')
      else:
        c = fread(4)
        if len(c) < 4:
          raise ValueError('EOF in new packet size byte 5.')
        size, = struct.unpack('>L', c)
    else:  # Old-format packet.
      packet_type = (b & 63) >> 2
      if packet_type == 0:
        raise ValueError('Packet type must not be 0.')
      lt = b & 3
      if lt == 0:
        c = fread(1)
        if not c:
          raise ValueError('EOF in old packet size 0.')
        size = ord(c)
      elif lt == 1:
        c = fread(2)
        if len(c) < 2:
          raise ValueError('EOF in old packet size 1.')
        size, = struct.unpack('>H', c)
      elif lt == 2:
        c = fread(4)
        if len(c) < 4:
          raise ValueError('EOF in old packet size 2.')
        size, = struct.unpack('>L', c)
      elif lt == 3:
        raise ValueError('Indeterminate packet size not supported.')
      else:
        raise ValueError('Unknown old packet tag: %d' % lt)
    if size:
      if packet_type in (9, 11, 18):
        if size > 8192:
          remaining, is_partial = (size - 8192) & ~8191, True
          while remaining > 0:
            size2 = min(remaining, 8192)
            data = fread(size2)
            if len(data) != size2:
              raise ValueError('EOF in partial packet.')
            yield packet_type, is_partial, data
            remaining -= size2
            size -= size2
        assert 0 < size <= 8192
      elif size > 46:
        if not (packet_type == 2 and size < 8192):
          # We could easily handle megabytes, but the output of `gpg
          # --symmetric' just doesn't have such packets.
          raise ValueError('Packet size unusually large: type %d, size %d' %
                           (packet_type, size))
      data = fread(size)
      if len(data) < size:
        raise ValueError('EOF in packet, type %d' % packet_type)
      is_partial = False
      yield packet_type, is_partial, data


def get_gpg_ascii_armor_fread(fread):
  import binascii  # For base64.

  def yield_data_chunks(_a2b=binascii.a2b_base64, _crc24=crc24, _buffer=buffer):
    buf, is_in_header, crc = '\n', True, _crc24('')

    try:
      while 1:
        data = fread(512)  # Anything >= 1 works here.
        if not data:
          raise ValueError('EOF in GPG ASCII armor.')
        data = data.replace('\r', '')
        if not data:
          continue
        if is_in_header:  # Skip over header.
          if buf[-1:] == '\n' and data[0] == '\n':
            data, is_in_header = data[1:], False
          else:
            i = data.find('\n\n')
            if i >= 0:
              data, is_in_header = data[i + 2:], False
            else:
              buf = data[-1:]  # Keep last '\n', if any.
              continue
          buf = ''
        i = data.find('-')
        if i >= 0:
          buf += data[:i].replace('\n', '')
          data = data[i:]
          break
        # This is a long string copy (`data' can be long), but there is no
        # easy way around it.
        buf += data.replace('\n', '')
        s = len(buf)
        if s > 12:
          t = (s - 9) & ~3  # Keep last 5 for checksum, keep 4 for last few bytes.
          i = buf.find('=')
          if 0 <= i < t:
            raise ValueError('Too much padding at end of GPG ASCII armor base64.')
          bdata, buf = _a2b(_buffer(buf, 0, t)), buf[t:]
          crc = _crc24(bdata, crc)
          yield bdata
      if len(data) < 26:
        data += fread(26 - len(data))
      if not (data.startswith('-----END PGP MESSAGE-----') and data[25 : 26] in '\r\n'):
        raise ValueError('Bad end of GPG ASCII armor.')
      t = buf.rfind('=')
      if t <= 0:
        raise ValueError('Missing GPG ASCII armor checksum.')
      if len(buf) != t + 5:
        raise ValueError('GPG ASCII armor checksum must be 4 bytes.')
      expected_crc = _a2b(_buffer(buf, t + 1))
      expected_crc, = struct.unpack('>L', '\0' + expected_crc)
      if buf[t - 2 : t] == '==':
        i = t - 2
      elif buf[t - 1 : t] == '=':
        i = t - 1
      else:
        i = t
      if buf.find('=') != i:
        raise ValueError('Too much padding at end of GPG ASCII armor base64.')
      bdata = _a2b(buf[:t])
      crc = _crc24(bdata, crc)
      if crc != expected_crc:
        raise ValueError('GPG ASCII armor checksum mismatch.')
      if bdata:
        yield bdata
    except binascii.Error:
      raise ValueError('Bad GPG ASCII armor data base64.')

  return iter_to_fread(yield_data_chunks())


def yield_gpg_packets(fread, has_ascii_armor_ary=None):
  while 1:
    c = fread(1)
    if not c:
      raise ValueError('EOF before GPG data.')
    if not c.isspace():
      break
  if c == '-':
    data = fread(27)
    if not (len(data) == 27 and data.startswith('-----BEGIN PGP MESSAGE-----'[1:]) and data[26] in '\r\n'):
      raise ValueError('GPG ASCII armor expected.')
    if has_ascii_armor_ary is not None:
      has_ascii_armor_ary.append(True)
    fread = get_gpg_ascii_armor_fread(fread)
    c = fread(1)
    if not c:
      raise ValueError('Empty GPG ASCII armor data.')
  elif has_ascii_armor_ary is not None:
    has_ascii_armor_ary.append(False)
  b, packet_type = ord(c), -1
  if b & 128:
    packet_type = (b & 63) >> ((~b >> 5) & 2)
  if packet_type != 3:  # packet_type == 3 (SKESK), c in '\x8c\x8d\x8e\xc3'.
    if packet_type < 0:
      raise ValueError('Bad GPG data, packet expected.')
    if not 1 <= packet_type <= 19:
      raise ValueError('Bad GPG data, packet expected, got unusual packet of type: %d' % packet_type)
    # TODO(pts): Add support for `gpg -e --sign': '\x90\x91\x92\xc4' (packet_type == 4), also packet_type == 2.
    if packet_type == 8:
      raise ValueError('GPG symmetric key encrypted data expected, got compressed data (probably public-key signed message).')
    if packet_type in (2, 4):
      raise ValueError('GPG symmetric key encrypted data expected, got public-key signed data.')
    if packet_type == 1:
      raise ValueError('GPG symmetric key encrypted data expected, got public-key encrypted data.')
    raise ValueError('Bad GPG symmetric encrypted data (SKESK packet expected), got packet of type: %d' % packet_type)
  for packet in yield_gpg_binary_packets(fread, c):
    yield packet


def open_symmetric_gpg(fread, passphrase, is_slow_cipher, is_slow_hash, show_info_func, do_show_session_key):
  # https://tools.ietf.org/html/rfc4880
  if not show_info_func:
    show_info_func = lambda msg: 0
  is_prev_partial, has_ascii_armor_ary = False, []
  cipher_algo = session_key = None
  iter_packets = yield_gpg_packets(fread, has_ascii_armor_ary)
  for packet_type, is_partial, data in iter_packets:
    break
  else:
    raise ValueError('EOF before SKESK packet.')
  # Symmetric-Key Encrypted Session Key Packet.
  if packet_type != 3:
    raise ValueError('Expected SKESK packet type, got: %d' % packet_type)
  if not 4 <= len(data) <= 46:
    raise ValueError('Bad GPG symmetric encrypted data (bad SKESK packet size).')
  assert not is_partial
  version, cipher_algo, s2k_mode, digest_algo = struct.unpack(
      '>BBBB', buffer(data, 0, 4))
  if version != 4:
    raise ValueError('SKESK version 4 expected, got %d' % version)
  i = 4
  if s2k_mode == 0:
    salt, count = '', 0
  else:
    salt = data[i : i + 8]
    if len(salt) < 8:
      raise ValueError('EOF in SKESK salt.')
    i += 8
    if s2k_mode == 3:
      if i >= len(data):
        raise ValueError('EOF in SKESK iterated-salted count.')
      b = ord(data[i])
      i += 1
      count = (16 + (b & 15)) << ((b >> 4) + 6)
    else:
      count = 0
  show_info_func('GPG symmetric cipher_algo=%s s2k_mode=%s digest_algo=%s count=%d len(salt)=%d len(encrypted_session_key)=%d has_ascii_armor=%d' %
                 (CIPHER_ALGOS_ALL.get(cipher_algo, cipher_algo), S2K_MODES.get(s2k_mode, s2k_mode), DIGEST_ALGOS.get(digest_algo, digest_algo), count, len(salt), len(data) - i, int(has_ascii_armor_ary[0])))
  if do_show_session_key:
    show_info_func('GPG symmetric encrypted_session_key=%r' % ':'.join((str(cipher_algo), data[i:].encode('hex').upper())))
  if cipher_algo not in CIPHER_ALGOS:
    raise ValueError('Unknown SKESK cipher_algo: %d' % cipher_algo)
  if s2k_mode not in S2K_MODES:
    raise ValueError('Unknown SKESK s2k_mode: %d' % s2k_mode)
  if digest_algo not in DIGEST_ALGOS:
    raise ValueError('Unknown SKESK digest_algo: %d' % digest_algo)
  digest_func = lambda data='': new_hash(DIGEST_ALGOS[digest_algo], data, is_slow_hash)
  show_info_func('GPG symmetric is_py_digest=%d' % int(is_python_function(digest_func().update)))
  keytable_size = KEYTABLE_SIZES[cipher_algo]
  for packet_type, is_partial, data2 in iter_packets:
    break
  else:
    raise ValueError('EOF after SKESK packet.')
  if packet_type == 9:
    has_mdc = False
    data_ary = [is_partial, buffer(data2)]
  elif packet_type == 18:
    has_mdc = True
    if not data2:
      raise ValueError('Integrity-protected packet too short.')
    version = ord(data2[0])
    if version != 1:
      raise ValueError('Integrity-protected packet version 1 expected, got: %d' % version)
    data_ary = [is_partial, buffer(data2, 1)]
  else:
    raise ValueError('Expected symmetric data packet type, got: %d' % packet_type)
  del data2

  if callable(passphrase):
    passphrase = passphrase()
  # Correct, same as:
  # gpg --list-packets -vvvvv --show-session-key --pinentry-mode loopback hellow4.bin.gpg
  session_key = get_gpg_s2k_string_to_key(keytable_size, salt, count, digest_func, passphrase)  # Slow.
  del passphrase, keytable_size, salt, digest_func

  if len(data) > i:  # Encrypted session key.
    if do_show_session_key:
      show_info_func('GPG symmetric derived_session_key_key=%r' % ':'.join((str(cipher_algo), session_key.encode('hex').upper())))
    if s2k_mode == 0:
      raise ValueError('Encrypted session key needs salt.')
    codebook, bs = get_gpg_cipher(cipher_algo, session_key, is_slow_cipher)
    strxor_bs = make_strxor(bs)  # For cipher_algo block size.
    encrypt_func = codebook.encrypt
    fre = encrypt_func('\0' * bs)
    session_key = []
    for i in xrange(i, len(data), bs):
      datae = data[i : i + bs]
      data1 = strxor_bs(datae + '\0' * (bs - len(datae)), fre)[:len(datae)]
      if session_key:
        session_key.append(data1)
      else:
        cipher_algo = ord(data1[0])
        if cipher_algo not in CIPHER_ALGOS:
          raise ValueError('Unknown encrypted session key cipher_algo: %d' % cipher_algo)
        session_key.append(data1[1:])  # Short copy.
      if len(datae) < bs:
        break
      fre = encrypt_func(datae)
    session_key = ''.join(session_key)
    if len(session_key) != KEYTABLE_SIZES[cipher_algo]:
      raise ValueError('Encrypted session key size must be %d for cipher_algo %s, got: %d' %
                       (KEYTABLE_SIZES[cipher_algo], CIPHER_ALGOS[cipher_algo], len(session_key)))
  if do_show_session_key:
    # Showing it with the same display style as gpg(1).
    show_info_func('GPG symmetric session_key=%r' % ':'.join((str(cipher_algo), session_key.encode('hex').upper())))

  def yield_data_chunks():
    if data_ary:
      is_partial, data = data_ary
      del data_ary[:]  # Save memory.
      yield data
      is_done = not is_partial
    for packet_type2, is_partial, data in iter_packets:
      if is_done:
        raise ValueError('Unexpected packet after symmetric data: %d' %
                         packet_type2)
      yield data
      is_done = not is_partial
    if not is_done:
      raise ValueError('Last packet must be a non-partial packet.')

  return cipher_algo, session_key, has_mdc, iter_to_fread(yield_data_chunks()), show_info_func


def get_yield_decompress_chunks(zd):
  """Returns a generator which yields reasonably-side decompressed chunks.

  Args:
    zd: A zlib.decompressobj (or compatible) instance.
  """
  zd_decompress = zd.decompress

  def yield_decompress_chunks(data):
    yield zd_decompress(data, 8192)
    while zd.unconsumed_tail:
      yield zd_decompress(zd.unconsumed_tail, 8192)

  return yield_decompress_chunks


class BadPassphraseError(ValueError):
  """Raised when a bad passphrase is detected early at decryption."""


def get_decrypt_symmetric_gpg_literal_packet_reader(
    fread,
    passphrase,  # This is the first argument, order of others can change.
    is_slow_cipher=False, is_slow_hash=False,
    show_info_func=None, do_show_session_key=False):
  # Don't add more arguments above, this function is used in
  # GpgSymmetricFileReader.
  _buffer = buffer
  cipher_algo, session_key, has_mdc, fread, show_info_func = open_symmetric_gpg(
      fread, passphrase, is_slow_cipher, is_slow_hash, show_info_func,
      do_show_session_key)
  del passphrase
  show_info_func(
      'GPG symmetric session has_mdc=%d cipher_algo=%s len(session_key)=%d' %
      (int(has_mdc), CIPHER_ALGOS_ALL.get(cipher_algo, cipher_algo), len(session_key)))
  #print (cipher_algo, session_key, has_mdc)
  strxor_2 = make_strxor(2)
  codebook, bs = get_gpg_cipher(cipher_algo, session_key, is_slow_cipher)
  show_info_func('GPG symmetric is_py_cipher=%d' % int(is_python_function(codebook.encrypt)))
  strxor_bs = make_strxor(bs)  # For cipher_algo block size.
  encrypt_func = codebook.encrypt
  fre = encrypt_func('\0' * bs)
  data = fread(bs)
  if len(data) != bs:
    raise ValueError('EOF in block 0.')
  data1 = strxor_bs(data, fre)
  fre = encrypt_func(data)
  if has_mdc:
    exp2 = data1[-2:]
    data = fread(bs)
    if len(data) != bs:  # Always true, encrypted data includes 22 bytes of MDC packet.
      raise ValueError('EOF in block 1.')
    mdc_obj = new_hash('sha1', data1, is_slow_hash)
    mdc_obj.update(exp2)
    data1 = strxor_bs(data, fre)
    if data1[:2] != exp2:  # We don't detect bad passphrase with P = 1./2**bs.
      raise BadPassphraseError('Bad passphrase (MDC repeat).')
    data1 = data1[2:]  # Short copy.
    # Number of blocks to which 22 + 4 bytes fit. See below why.
    mdc_min_queue_size = (22 + 4 + bs - 1) // bs
  else:
    exp2 = strxor_2(fre[:2], data1[-2:])
    got2 = fread(2)
    if len(got2) != 2:
      raise ValueError('EOF in block got2.')
    if exp2 != got2:  # We don't detect bad passphrase with P = 1./2**bs.
      raise BadPassphraseError('Bad passphrase (non-MDC repeat).')
    fre = encrypt_func(data[2:] + got2)  # Short copy.
    data = fread(bs)
    # On empty plaintext, len(data) == 8 here.
    if len(data) < 2:
      raise ValueError('EOF in block 1.')
    data1 = strxor_bs(data + '\0' * (bs - len(data)), fre)[:len(data)]
    mdc_obj, mdc_min_queue_size = None, 0
  # By doing these checks we decrease the P above by better than /2**5.
  if data1[0] == '\xa3':  # Indeterminate, packet_type == 8.
    if ord(data1[1]) >= 0x20:  # GPG 2.1.18 has 0..3 defined.
      raise ValueError('Bad passphrase (invalid compress_algo).')
    compress_algo = ord(data1[1])
    if mdc_obj:
      mdc_obj.update(data1[:2])
    data1 = data1[2:]  # Short copy.
  else:
    if mdc_obj and data1.startswith('\xd3\x14'):
      pass  # MDC without any literal packet.
    elif data1[0] in '\xac\xad\xae\xcb':
      pass  # Literal packet, non-indeterminate.
    else:
      raise BadPassphraseError('Bad passphrase (bad packet type).')
    compress_algo = 0  # Uncompressed.
  show_info_func('GPG symmetric compress_algo=%s' %
                 (COMPRESS_ALGOS.get(compress_algo, compress_algo),))
  zd = zd_decompress = None
  if compress_algo == 0:
    pass  # Uncompressed.
  elif compress_algo == 1:
    import zlib  # ImportError: no flate decompressor in Python.
    zd = zlib.decompressobj(-13)
  elif compress_algo == 2:
    import zlib  # ImportError: no flate decompressor in Python.
    zd = zlib.decompressobj()
  elif compress_algo == 3:
    import bz2  # ImportError: no bzip2 decompressor in Python.
    zd = bz2.BZ2Decompressor()
  else:
    raise ValueError('Unknown compress_algo: %d' % compress_algo)
  zdml = None
  if zd:
    zd_decompress = zd.decompress
    try:
      zd_decompress('', 42)
      if zd.unconsumed_tail != '':
        raise ValueError
      # Limit memory usage.
      zdml = get_yield_decompress_chunks(zd)  # zlib has it.
    except (TypeError, ValueError, AttributeError):
      zdml = None  # lambda data1, _zdd: (_zdd(data1,))  # bz2 doesn't have it.

  def yield_data_chunks(data1, data, encrypt_func, mdc_obj):
    if mdc_obj:
      # We don't process data1 yet, because we want to remove the MDC packet
      # (22 bytes, packet_type == 19, starts with '\xd3\x14') from the end first.
      mdc_queue = data1
    else:
      mdc_queue = ''
      if zdml:
        for chunk in zdml(data1):
          yield chunk
      elif zd_decompress:
        yield zd_decompress(data1)  # Can raise zlib.error.
      else:
        yield data1
    _fast_strxor = not is_python_function(encrypt_func) and fast_strxor
    if len(data) == bs:
      bs2bs = (bs * (2 + mdc_min_queue_size), bs)
      bsmdc = bs * mdc_min_queue_size
      while 1:
        data2 = fread(bs)
        if len(data2) < bs:
          fre = encrypt_func(data)
          mdc_queue += strxor_bs(data2 + '\0' * (bs - len(data2)), fre)[:len(data2)]
          break
        data3 = _fast_strxor and fread(bs2bs)
        if data3:  # <FAST-DECRYPTION>: large prebuffered chunks.
          lbs = bs + len(data3)
          # Most of the decryption time is spent in this block below.
          #
          # hellow5long.bin.gpg is based on 33636451 bytes of uncompressible plaintext.
          # time gpg -d --pinentry-mode loopback <hellow5long.bin.gpg >hellow5long.out
          # 3.168s user
          # $ time ./tinygpgs -d abc <hellow5long.bin.gpg >hellow5long.out
          # 4.512s user
          #
          # Typical lbs is 8192 bytes (for 8192-byte packets).
          # For hellow3.bin.gpg, lbs is 384 bytes.
          if mdc_queue:  # Flush mdc_queue before critical path.
            mdc_obj.update(mdc_queue)
            if zdml:
              for chunk in zdml(mdc_queue):
                yield chunk
            elif zd_decompress:
              yield zd_decompress(mdc_queue)
            else:
              yield mdc_queue
          # A single call to _fast_strxor is faster than
          # Crypto.Cipher._AES.MODE_CFB with segment_size=(bs << 3).
          #
          # Test vectors:
          # https://github.com/ircmaxell/PHP-PasswordLib/blob/master/test/Data/Vectors/aes-cfb.test-vectors
          # , so we usse manual strxor instead.
          #
          # Slow copy in: data3[:], (data2 + data3), +=.
          datad, data3, data = _fast_strxor(encrypt_func(data), data2), data3[:], data3[lbs - bs - bs:]
          datad += _fast_strxor(encrypt_func(_buffer((data2 + data3), 0, lbs - bs)), data3)
          data2 = _buffer(datad, 0, lbs - bsmdc)
          if mdc_obj:
            mdc_obj.update(data2)
          if zdml:
            for chunk in zdml(data2):
              yield chunk
          elif zd_decompress:
            yield zd_decompress(data2)
          else:
            yield data2
          if mdc_obj:  # Fill mdc_queue again.
            mdc_queue = datad[lbs - bsmdc : lbs]
        else:  # This branch happens only with empty*.bin.gpg, not even hellow*.bin.gpg.
          fre, data = encrypt_func(data), data2
          data1 = strxor_bs(data, fre)
          if mdc_obj:
            if len(mdc_queue) >= bsmdc:
              data2 = _buffer(mdc_queue, 0, bs)
              mdc_obj.update(data2)
              if zdml:
                for chunk in zdml(data2):
                  yield chunk
              elif zd_decompress:
                yield zd_decompress(data2)
              else:
                yield data2
              mdc_queue = mdc_queue[bs:] + data1  # Short copy.
            else:
              mdc_queue += data1  # Short copy.
            # Now len(mdc_queue) >= bsmdc, and it contains enough
            # bytes (>= 22) for an MDC packet: mdc_min_queue_size * bs -
            # len(exp2) - len('\xd3\x14') >= 22.
          else:
            if zdml:
              for chunk in zdml(data1):
                yield chunk
            elif zd_decompress:
              yield zd_decompress(data1)
            else:
              yield data1
    if mdc_obj:
      if len(mdc_queue) < 22:
        raise ValueError('EOF in encrypted data before MDC packet.')
      if mdc_queue[-22 : -20] != '\xd3\x14':  # packet_type == 19.
        raise ValueError('Bad MDC packet header.')
      mdc_queue, mdc = _buffer(mdc_queue, 0, len(mdc_queue) - 22), _buffer(mdc_queue, len(mdc_queue) - 20)
      mdc_obj.update(mdc_queue)
      mdc_obj.update('\xd3\x14')
      if _buffer(mdc_obj.digest()) == mdc:
        mdc_obj = None
    if mdc_queue:
      if zdml:
        for chunk in zdml(mdc_queue):
          yield chunk
      elif zd_decompress:
        yield zd_decompress(mdc_queue)
      else:
        yield mdc_queue
    if zd and getattr(zd, 'flush', None):
      yield zd.flush()
    # Do this after the very last yield.
    if mdc_obj:
      raise ValueError('MDC mismatch, message may have been tampered with.')

  return iter_to_fread(yield_data_chunks(data1, data, encrypt_func, mdc_obj))


LITERAL_TYPES = 'btul1'


def skip_gpg_literal_packet_header(data):
  if len(data) < 6:
    raise ValueError('First literal packet too short.')
  literal_type, filename_size = struct.unpack('>cB', data[:2])
  if literal_type not in LITERAL_TYPES:
    raise ValueError('Bad literal type: %r' % literal_type)
  if len(data) < 6 + filename_size:
    raise ValueError('First literal packet too short for filename.')
  # First we get filename, then the date (4 bytes), 4 byte Unix timestamp.
  return buffer(data, 6 + filename_size)


def copy_gpg_literal_data(fread, of):
  done_state, fwrite = 0, of.write
  for packet_type, is_partial, data in yield_gpg_binary_packets(fread):
    if done_state == 2:
      if packet_type == 2 and not is_partial:
        continue  # Ignore public-key signature.
      raise ValueError('Unexpected packet after literal data: %d' %
                       packet_type)
    if packet_type != 11:
      if packet_type == 4 and not is_partial and done_state == 0:
        continue  # Ignore one-pass packet fur public-key signature.
      raise ValueError('Literal packet expected, got: %d' % packet_type)
    if done_state == 0:
      data = skip_gpg_literal_packet_header(data)
    fwrite(data)
    done_state = 1 + (not is_partial)
  if done_state == 1:
    raise ValueError('Missing last literal packet.')


def yield_gpg_literal_data_chunks(fread):
  it = yield_gpg_binary_packets(fread)
  data, is_done = '', True
  for packet_type, is_partial, data in it:
    if packet_type != 11:
      if packet_type == 4 and not is_partial:
        continue  # Ignore one-pass packet fur public-key signature.
      raise ValueError('Literal packet expected, got: %d' % packet_type)
    data = skip_gpg_literal_packet_header(data)[:]
    yield ''  # Indicate successful init.
    yield data
    is_done = not is_partial
    break
  else:
    yield ''  # Indicate successful init.
  for packet_type, is_partial, data in it:
    if is_done:
      if packet_type == 2 and not is_partial:
        continue  # Ignore public-key signature.
      raise ValueError('Unexpected packet after literal data: %d' %
                       packet_type)
    if packet_type != 11:
      raise ValueError('Literal packet expected, got: %d' % packet_type)
    yield data
    is_done = not is_partial
  if not is_done:
    raise ValueError('Missing last literal packet.')


def decrypt_symmetric_gpg(fread, of, *args, **kwargs):
  fread = get_decrypt_symmetric_gpg_literal_packet_reader(fread, *args, **kwargs)
  try:
    copy_gpg_literal_data(fread, of)
  finally:
    of.flush()  # Flush before raising MDC mismatch or something else.


# --- GPG encryption.


def get_random_bytes_python(size):
  import random
  return ''.join(chr(random.randrange(0, 255)) for _ in xrange(size))


def get_random_bytes_default(size, _functions=[]):
  if size == 0:
    return ''
  if not _functions:
    import os
    try:
      data = os.urandom(1)  # More secure than get_random_bytes_python.
      if len(data) != 1:
        raise ValueError
      _functions.append(os.urandom)
    except (ImportError, AttributeError, TypeError, ValueError, OSError):
      _functions.append(get_random_bytes_python)

  return _functions[0](size)


def get_short_gpg_packet(packet_type, data):
  if len(data) > 191:
    raise ValueError('Short GPG packet must be at most 191 bytes, got: %d' % len(data))
  if not 1 <= packet_type <= 63:
    raise ValueError('Invalid GPG packet type: %d' % packet_type)
  return struct.pack('>BB', 192 | packet_type, len(data)) + data


def yield_partial_gpg_packet_chunks(packet_type, data, fread, buflog2cap, _pack=struct.pack):
  if not 1 <= packet_type <= 63:
    raise ValueError('Invalid GPG partial packet type: %d' % packet_type)
  if buflog2cap > 30:  # The GPG file format doesn't support more.
    raise ValueError('buflog2cap must be at most 30, got: %d' % buflog2cap)
  if buflog2cap < 9:  # The GPG file format doesn't support less for the first partial packet.
    raise ValueError('buflog2cap must be at least 9, got: %d' % buflog2cap)
  bufsize = 1 << buflog2cap
  if len(data) > bufsize:
    raise ValueError('Initial partial data too long.')
  data += fread(bufsize - len(data))
  if len(data) < bufsize:
    if len(data) < 192:
      yield _pack('>BB', 192 | packet_type, len(data))
    elif len(data) < 8192 + 192:
      b = len(data) - 192
      yield _pack('>BBB', 192 | packet_type, 192 | b >> 8, b & 255)
    elif packet_type < 16:
      yield _pack('>BL', 130 | (packet_type << 2), len(data))
    else:
      yield _pack('>BBL', 192 | packet_type, 255, len(data))
    yield data
  else:
    cont_size_spec = _pack('>B', 224 | buflog2cap)
    yield _pack('>Bc', 192 | packet_type, cont_size_spec)
    while 1:
      yield data
      data = fread(bufsize)
      if len(data) < bufsize:
        break
      yield cont_size_spec
    if len(data) < 192:
      yield _pack('>B', len(data))
    elif len(data) < 8192 + 192:
      b = len(data) - 192
      yield _pack('>BB', 192 | b >> 8, b & 255)
    else:
      yield _pack('>BL', 255, len(data))
    yield data


def write_partial_gpg_packet_chunks(fwrite, packet_type, data, fread, buflog2cap, _pack=struct.pack):
  # Similar to yield_partial_gpg_packet_chunks, but calls fwrite instead of
  # yield. Added for performance reasons.
  if not 1 <= packet_type <= 63:
    raise ValueError('Invalid GPG partial packet type: %d' % packet_type)
  if buflog2cap > 30:  # The GPG file format doesn't support more.
    raise ValueError('buflog2cap must be at most 30, got: %d' % buflog2cap)
  if buflog2cap < 9:  # The GPG file format doesn't support less for the first partial packet.
    raise ValueError('buflog2cap must be at least 9, got: %d' % buflog2cap)
  bufsize = 1 << buflog2cap
  if len(data) > bufsize:
    raise ValueError('Initial partial data too long.')
  data += fread(bufsize - len(data))
  if len(data) < bufsize:
    if len(data) < 192:
      fwrite(_pack('>BB', 192 | packet_type, len(data)))
    elif len(data) < 8192 + 192:
      b = len(data) - 192
      fwrite(_pack('>BBB', 192 | packet_type, 192 | b >> 8, b & 255))
    elif packet_type < 16:
      fwrite(_pack('>BL', 130 | (packet_type << 2), len(data)))
    else:
      fwrite(_pack('>BBL', 192 | packet_type, 255, len(data)))
    fwrite(data)
  else:
    cont_size_spec = _pack('>B', 224 | buflog2cap)
    fwrite(_pack('>Bc', 192 | packet_type, cont_size_spec))
    while 1:  # This is the critical path.
      fwrite(data)
      data = fread(bufsize)
      if len(data) < bufsize:
        break
      fwrite(cont_size_spec)
    if len(data) < 192:
      fwrite(_pack('>B', len(data)))
    elif len(data) < 8192 + 192:
      b = len(data) - 192
      fwrite(_pack('>BB', 192 | b >> 8, b & 255))
    else:
      fwrite(_pack('>BL', 255, len(data)))
    fwrite(data)


# Default values mostly same as of GPG 1.x, GPG <2.1 (checked 1.0.6 and 1.4.18).
def get_encrypt_symmetric_gpg_params(
    passphrase,  # This is the first argument, order of others can change.
    is_slow_cipher=False, is_slow_hash=False, cipher='cast5', s2k_digest='sha1', compress='zip', compress_level=6, s2k_mode=3, s2k_count=65536, salt=None,
    do_mdc=True,  # No fixed default in gpg(1), let's play it safe with True.
    buflog2cap=13, plain_filename='', mtime=0, literal_type='b', do_add_ascii_armor=False, show_info_func=None, do_show_session_key=False, iv=None):
  if not show_info_func:
    show_info_func = lambda msg: 0
  _pack = struct.pack
  do_mdc = bool(do_mdc)
  cipher = cipher.lower()
  for cipher_algo, cipher2 in sorted(CIPHER_ALGOS.iteritems()):
    if cipher2 == cipher:
      break
  else:
    raise ValueError('Unknown GPG cipher: %s' % cipher)
  s2k_digest = s2k_digest.replace('-', '').lower()
  for digest_algo, s2k_digest2 in sorted(DIGEST_ALGOS.iteritems()):
    if s2k_digest2 == s2k_digest:
      break
  else:
    raise ValueError('Unknown GPG digest (for s2k): %s' % s2k_digest)
  compress = compress.lower()
  if compress == 'none':
    compress_algo = 0
  else:
    for compress_algo, compress2 in sorted(COMPRESS_ALGOS.iteritems()):
      if compress2 == compress:
        break
    else:
      raise ValueError('Unknown GPG compressor: %s' % compress)
  if s2k_mode == 0:
    salt, count = '', 0
  elif s2k_mode in (1, 3):
    salt = (salt or '')[:8]
    if len(salt) < 8:
      salt = get_random_bytes_default(8 - len(salt))
    if len(salt) != 8:
      raise ValueError('GPG symmetric salt must be %d bytes, got: %d' % len(salt))
    if s2k_mode == 3:
      count = s2k_count
    else:
      count = 0
  else:
    raise ValueError('Invalid s2k mode: %r' % (s2k_mode,))
  if count < 0:
    raise ValueError('s2k count must be nonnegative, got: %d' % count)
  if compress_algo == 0 or compress_level <= 0:
    ze = None
  elif compress_algo == 1:
    import zlib  # ImportError: no flate decompressor in Python.
    ze = zlib.compressobj(compress_level, 8, -13)
  elif compress_algo == 2:
    import zlib  # ImportError: no flate decompressor in Python.
    ze = zlib.compressobj(compress_level)
  elif compress_algo == 3:
    import bz2  # ImportError: no bzip2 decompressor in Python.
    ze = bz2.BZ2Compressor(compress_level)
  else:
    raise ValueError('Unknown compress_algo: %d' % compress_algo)
  digest_func = lambda data='': new_hash(s2k_digest, data, is_slow_hash)
  keytable_size = KEYTABLE_SIZES[cipher_algo]
  codebook0, bs = get_gpg_cipher(cipher_algo, '\0' * keytable_size, is_slow_cipher)
  plaintext_salt = (iv or '')[:bs]
  if len(plaintext_salt) < bs:
    plaintext_salt = get_random_bytes_default(bs - len(plaintext_salt))
  if s2k_mode == 3:
    if count == 65536:  # Shortcut.
      bestb = 0x60
    else:
      bestb, bestdiff, bestcount = 0, abs(1024 - count), 1024
      for b in xrange(255):
        count2 = (16 + (b & 15)) << ((b >> 4) + 6)
        diff2 = abs(count2 - count)
        if diff2 < bestdiff:
          bestb, bestdiff, bestcount = b, diff2, count2
      count = bestcount  # Nearest count.
  if buflog2cap < 1:
    buflog2cap = 0
  while bs > (1 << buflog2cap):
    buflog2cap += 1
  if buflog2cap > 30:
    # The new-format packet header doesn't support more than 30.
    raise ValueError('buglog2cap must be at most 30, got: %d' % buflog2cap)
  if show_info_func:
    show_info_func(
        'GPG symmetric encrypt cipher_algo=%s(%d) is_py_cipher=%d s2k_mode=%s(%d) s2k_digest_algo=%s(%d) is_py_digest=%d '
        's2k_count=%d len(s2k_salt)=%d compress_algo=%s(%d) compress_level=%d len(encrypted_session_key)=%d do_mdc=%d '
        'len(session_key)=%d bufcap=%d literal_type=%r plain_filename=%r mtime=%d do_add_ascii_armor=%d' %
        (CIPHER_ALGOS_ALL.get(cipher_algo, cipher_algo), cipher_algo,
         int(is_python_function(codebook0.encrypt)),
         S2K_MODES.get(s2k_mode, s2k_mode), s2k_mode,
         DIGEST_ALGOS.get(digest_algo, digest_algo), digest_algo,
         int(is_python_function(digest_func().update)),
         count, len(salt),
         COMPRESS_ALGOS.get(compress_algo, compress_algo), compress_algo, compress_level,
         0, int(do_mdc), keytable_size, 1 << buflog2cap, literal_type, plain_filename, mtime, int(bool(do_add_ascii_armor))))
  if buflog2cap < 9:  # The GPG file format doesn't support less for the first partial packet.
    raise ValueError('buflog2cap must be at least 9, got: %d' % buflog2cap)
  if len(plain_filename) > 255:
    raise ValueError('plain_filename too long, must be at most 255 bytes, got: %d' % len(plain_filename))
  if not literal_type or literal_type not in LITERAL_TYPES:
    raise ValueError('Bad literal type: %r' % literal_type)
  if callable(passphrase):
    passphrase = passphrase()
  session_key = get_gpg_s2k_string_to_key(keytable_size, salt, count, digest_func, passphrase)  # Slow.
  if do_show_session_key and show_info_func:
    show_info_func('GPG symmetric encrypt session_key=%r' % ':'.join((str(cipher_algo), session_key.encode('hex').upper())))
  codebook, bs = get_gpg_cipher(cipher_algo, session_key, is_slow_cipher)
  try:
    cfb_encrypt = get_gpg_cipher(cipher_algo, session_key, is_slow_cipher, '\0' * bs)[0].encrypt
  except (BadCfbCipher, ImportError):
    cfb_encrypt = None
  encrypt_func = codebook.encrypt
  header = _pack('>BBBB%dsB' % len(salt), 4, cipher_algo, s2k_mode, digest_algo, salt, bestb)
  if len(header) > 191:
    raise ValueError('SKESK packet too long.')
  header = struct.pack('>BB', 192 | 3, len(header)) + header
  if do_mdc:
    first_plaintext_chunk = plaintext_salt + plaintext_salt[-2:]
    mdc_obj = new_hash('sha1', '', is_slow_hash)
    mdc_update = mdc_obj.update
  else:
    mdc_obj = mdc_update = None
    first_plaintext_chunk = ''
  if ze:
    chunk = _pack('>BB', 0xa3, compress_algo)  # packet_type == 8.
    first_plaintext_chunk += chunk
  fr = '\0' * bs
  if mdc_obj:
    packet_type, packet_header = 18, '\1'
  else:
    strxor_bs = make_strxor(bs)
    data = strxor_bs(plaintext_salt, encrypt_func(fr))
    fr = data
    got2 = make_strxor(2)(encrypt_func(fr)[:2], plaintext_salt[-2:])
    packet_type, packet_header = 9, fr + got2
    fr = data[2:] + got2  # Short copy.
    # Set the IV in cfb_encrypt to fr. '\2' * bs is arbitrary.
    fr1 = cfb_encrypt(strxor_bs(encrypt_func(cfb_encrypt('\2' * bs)), fr))
    assert fr1 == fr
  literal_header = struct.pack('>cB%dsL' % len(plain_filename), literal_type, len(plain_filename), plain_filename, mtime)
  return header, encrypt_func, bs, cfb_encrypt, plaintext_salt, mdc_obj, mdc_update, first_plaintext_chunk, ze, packet_type, packet_header, fr, literal_header, buflog2cap, do_add_ascii_armor


def get_gpg_armor_trailer(abuf, asize, acrc, _b2a):
  output = []
  if asize:
    adata = ''.join(abuf)
    adata = _b2a(adata)
    output.append(adata)
    if not adata.endswith('\n'):
      output.append('\n')
  output.append('=')
  output.append(_b2a(struct.pack('>L', acrc)[1:]))
  output.append('\n-----END PGP MESSAGE-----\n')
  return ''.join(output)


def encrypt_symmetric_gpg(fread, of, *args, **kwargs):
  _buffer = buffer
  header, encrypt_func, bs, cfb_encrypt, plaintext_salt, mdc_obj, mdc_update, first_plaintext_chunk, ze, packet_type, packet_header, fr, literal_header, buflog2cap, do_add_ascii_armor = get_encrypt_symmetric_gpg_params(
      *args, **kwargs)
  bufcap = 1 << buflog2cap

  def yield_plaintext_chunks():
    if mdc_obj:
      mdc_update(first_plaintext_chunk)
    yield first_plaintext_chunk
    ufread = iter_to_fread(yield_partial_gpg_packet_chunks(11, literal_header, fread, buflog2cap))
    ze_compress = ze and ze.compress
    while 1:
      data = ufread(bufcap)
      if not data:
        break
      if ze_compress:
        data = ze_compress(data)
      if mdc_obj:
        mdc_update(data)
      yield data
    if ze:
      data = ze.flush()
      if mdc_obj:
        mdc_update(data)
      yield data
    if mdc_obj:
      mdc_update('\xd3\x14')
      yield '\xd3\x14' + mdc_obj.digest()

  def yield_ciphertext_chunks(fr=fr):
    strxor_bs = make_strxor(bs)
    pfread = iter_to_fread(yield_plaintext_chunks())
    pfread_size = bufcap
    pfread_size -= pfread_size % bs
    assert pfread_size % bs == 0
    if pfread_size < (bs << 1):  # Ignore small pfread_size, read bs at a time. <SLOW-ENCRYPTION>.
      while 1:
        data = pfread(bs)
        if len(data) < bs:
          if data:
            yield strxor_bs(data + '\0' * (bs - len(data)), encrypt_func(fr))[:len(data)]
          break
        data = strxor_bs(data, encrypt_func(fr))  # CFB mode.
        yield data
        fr = data
    elif cfb_encrypt:  # <FAST-ENCRYPTION>.
      buf = []
      data = pfread(pfread_size)
      while data:
        if len(data) % bs:  # Unlikey, near end.
          ldbs = len(data) - len(data) % bs
          yield cfb_encrypt(_buffer(data, 0, ldbs))
          data = data[ldbs:]
          yield cfb_encrypt(data + '\0' * (bs - len(data)))[:len(data)]
          break
        else:  # Likely, critical path.
          yield cfb_encrypt(data)
        data = pfread(pfread_size)
    else:  # <MEDIUM-ENCRYPTION>.
      # This is <2.1387 times slower than FAST-ENCRYPTION above, but it's
      # 3.1834 times faster than <SLOW-ENCRYPTION> if pfread_size is 8192 bytes.
      pfread_size -= pfread_size % bs
      buf = []
      data = pfread(pfread_size)
      while data:
        lda = len(data)
        ldbs = lda - lda % bs
        data, datax = data[:ldbs], data[ldbs:]
        del buf[:]
        for i in xrange(0, ldbs, bs):
          buf.append(strxor_bs(data[i : i + bs], encrypt_func(fr)))
          fr = buf[-1]
        yield ''.join(buf)
        if datax:
          yield strxor_bs(datax + '\0' * (bs - len(datax)), encrypt_func(fr))[:len(datax)]
          break
        data = pfread(pfread_size)

  efread, of_write = iter_to_fread(yield_ciphertext_chunks(fr)), of.write
  if do_add_ascii_armor:
    # We treat all output files as binary, using '\n' as line separator.
    # This is by design and for simplicity.
    import binascii
    _b2a, _crc24 = binascii.b2a_base64, crc24
    abuf, asize, acrc = [header], len(header), _crc24(header)
    del header
    of_write('-----BEGIN PGP MESSAGE-----\n\n')
    for bdata in yield_partial_gpg_packet_chunks(packet_type, packet_header, efread, buflog2cap):
      abuf.append(bdata)
      asize += len(bdata)
      # In Python 2, calling _crc24 on an str many times is faster than
      # calling it on a buffer multiple times.
      acrc = _crc24(bdata, acrc)  # Very slow, no C extension alternative.
      if asize >= 48:
        adata, lam = ''.join(abuf), asize % 48
        lal = asize - lam
        # We need a loop here so that we get '\n' after each 48 (+16) bytes.
        for i in xrange(0, lal, 48):
          of_write(_b2a(_buffer(adata, i, 48)))  # Contains trailing '\n'.
        abuf[:] = (adata[lal:],)
        adata, asize = (), lam
    of_write(get_gpg_armor_trailer(abuf, asize, acrc, _b2a))
  else:
    of_write(header)
    del header
    write_partial_gpg_packet_chunks(of_write, packet_type, packet_header, efread, buflog2cap)


def get_cfb_encrypt_func(encrypt_func, bs, fr):  # fr is IV.
  if len(fr) != bs:
    raise ValueError('CFB fr must be %d bytes, got: %d' % bs, len(fr))
  strxor_bs = make_strxor(bs)
  fr_ary = [fr]

  def cfb_encrypt(data):
    ld = len(data)
    if ld % bs:
      raise ValueError('CFB data size must be divisible by %d bytes, got: %d' % bs, ld)
    buf, fr = [], fr_ary[0]
    for i in xrange(0, ld, bs):
      buf.append(strxor_bs(encrypt_func(fr), data[i : i + bs]))
      fr = buf[-1]
    fr_ary[0] = fr
    return ''.join(buf)

  return cfb_encrypt


def get_last_nonpartial_packet_header(size, packet_type, _pack=struct.pack):
  if packet_type > 0:
    if size < 192:
      return _pack('>BB', 192 | packet_type, size)
    elif size < 8192 + 192:
      b = size - 192
      return _pack('>BBB', 192 | packet_type, 192 | b >> 8, b & 255)
    elif packet_type < 16:
      return _pack('>BL', 130 | (packet_type << 2), size)
    else:
      return _pack('>BBL', 192 | packet_type, 255, size)
  else:
    if size < 192:
      return _pack('>B', size)
    elif size < 8192 + 192:
      b = size - 192
      return _pack('>BB', 192 | b >> 8, b & 255)
    else:
      return _pack('>BL', 255, size)
