# by pts@fazekas.hu at Thu Nov 28 22:09:47 CET 2019

"""GPG-compatible public-key encryption."""

import binascii
import struct

from tinygpgs import gpgs

from tinygpgs.pyx import xrange, to_hex_str, ensure_binary, callable, ensure_str, int_from_bytes_be, buffer, binary_type


def parse_mpis(count, data, i):
  """Parses and returns count GPG multiprecision integers."""
  result = []
  while count > 0:
    count -= 1
    if i + 2 > len(data):
      raise ValueError('MPI too short.')
    bitsize, = struct.unpack('>H', data[i : i + 2])
    i += 2
    size = (bitsize + 7) >> 3
    if i + size > len(data):
      raise ValueError('MPI data too short.')
    result.append((bitsize, data[i : i + size]))
    i += size
  return result, i


def parse_pstring(data, i):
  """Parses and returns a Pascal string."""
  if i >= len(data):
    raise ValueError('pstring too short.')
  size, = struct.unpack('>B', data[i : i + 1])
  i += 1
  if i + size > len(data):
    raise ValueError('pstring data too short.')
  return data[i : i + size], i + size


def int_to_bytes_be(i, size):
  if callable(getattr(i, 'to_bytes', None)):  # Python >=3.2.
    return i.to_bytes(size, 'big')  # Can raise OverflowError.
  data = ensure_binary(binascii.unhexlify(ensure_binary('%%0%dx' % (size << 1) % i)))
  if len(data) != size:
    raise ValueError('Integer does not fit to %d bytes.' % size)
  return data


def build_mpi(i, bit_size):
  """bit_size is just an upper bound for the number of bits in i."""
  if i < 0:
    raise ValueError('MPI must be nonnegative.')
  if i >> bit_size:
    raise ValueError('MPI too long.')
  if i == 0:
    return b'\0\0'  # TODO(pts): Should this be b'\0\1\0' instead?
  size = (bit_size + 7) >> 3
  data = int_to_bytes_be(i, size)
  i, zero = 0, b'\0'[0]
  while data[i] == zero:
    i += 1
  data = data[i:]
  b = ord(data[:1])
  i = 1
  while b >> i:
    i += 1
  return struct.pack('>H', (len(data) << 3) + (i - 8)) + data


def curve25519_donna_scalarmult_int(n, p=9):
  """Performs scalarmult on the CV25519 elliptic curve.

  Args:
    n: An integer (scalar of an EC point).
    p: An integer containing the x coordinate of a group element (point on the EC).
  """
  k = (n & ~(1 << 255 | 7)) | 1 << 254
  ql, x1, x2, z2, x3, z3, do_swap = 2 ** 255 - 19, p, 1, 0, p, 1, 0
  for t in xrange(254, -1, -1):
    kt = (k >> t) & 1
    if do_swap ^ kt:
      x2, x3, z2, z3 = x3, x2, z3, z2
    do_swap = kt
    a, b = (x2 + z2) % ql, (x2 - z2) % ql
    aa, bb = (a * a) % ql, (b * b) % ql
    c, d = (x3 + z3) % ql, (x3 - z3) % ql
    da, cb = d * a % ql, c * b % ql
    d1, d2 = da + cb, da - cb
    x3, z3 = d1 * d1 % ql, x1 * d2 * d2 % ql
    x2, e = aa * bb % ql, (aa - bb) % ql
    z2 = e * (aa + 121665 * e) % ql
  if do_swap:
    x2, x3, z2, z3 = x3, x2, z3, z2
  return (x2 * pow(z2, ql - 2, ql)) % ql


# It starts with the size (10 bytes after the first byte).
# CV25519 curve OID (1.3.6.1.4.1.3029.1.5.1).
CV25519_OID = b'\x0a\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01'


def aes_key_wrap(keytable, data, is_slow_cipher=False, _pack=struct.pack, _unpack=struct.unpack):
  # https://tools.ietf.org/html/rfc3394
  if len(data) & 7:
    raise ValueError('Input data size of aes_key_wrap must be divisible by 8, got: %d' % len(data))
  r, n = [None], len(data) >> 3
  n1 = n + 1
  for i in xrange(1, n1):
    r.append(data[(i << 3) - 8 : (i << 3)])
  a = b'\xa6' * 8  # IV.
  encrypt_func = gpgs.get_cipher_cons('aes-256', is_slow_cipher, 0)[0](keytable).encrypt
  for j in xrange(6):
    for i in xrange(1, n1):
      b = encrypt_func(a + r[i])
      a, r[i] = _pack('>Q', _unpack('>Q', b[:8])[0] ^ (n * j + i)), b[8:]
  r[0] = a
  return b''.join(r)


def pk_encrypt_session_key(pk_encryption_key, cipher_algo, session_key, is_slow_cipher, is_slow_hash):
  d = pk_encryption_key
  pk_algo = d['pk_algo']
  if b'\0'[0]:  # Python 2, iterating over str yields 1-char strs.
    checksum = sum(ord(b) for b in session_key)
  else:
    checksum = sum(b for b in session_key)
  if pk_algo == 1:  # RSA.
    n = d['n']
  elif pk_algo == 16:  # Elgamal.
    n = d['p']
  elif pk_algo == 18:  # ECDH CV25519.
    # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-13.5
    v = int_from_bytes_be(gpgs.get_random_bytes_default(32))
    # Reversing because public keys are stored in '\40' little endian order.
    v_pk = int_to_bytes_be(curve25519_donna_scalarmult_int(v), 32)[::-1]
    s = int_to_bytes_be(curve25519_donna_scalarmult_int(v, int_from_bytes_be(d['pk'][::-1])), 32)[::-1]
    del v
    # m = symm_alg_ID || session_key || checksum || pkcs5_padding;
    data = struct.pack('>B%dsH' % len(session_key), cipher_algo, session_key, checksum)
    if len(data) < 40:  # Obfuscate len(session_key).
      padding_size = 40 - len(data)
    else:
      padding_size = 8 - (len(data) & 7)
    data += struct.pack('>B', padding_size) * padding_size  # PKCS#5.
    # curve_OID_len = (byte)len(curve_OID);
    # Param = curve_OID_len || curve_OID || public_key_alg_ID || 03 || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous Sender    " || recipient_fingerprint;
    pk_algo_id = 18  # ECDH.
    kdf_digest_algo, kek_cipher_algo = struct.unpack('>BB', d['kdfp'][:2])
    kdf_hash = gpgs.DIGEST_ALGOS[kdf_digest_algo]  # KeyError if unknown.
    if kek_cipher_algo not in (7, 8, 9):
      raise ValueError('Expected AES cipher for KEK, got: %s' % gpgs.CIPHER_ALGOS.get(kek_cipher_algo, kek_cipher_algo))
    keytable_size = gpgs.KEYTABLE_SIZES[kek_cipher_algo]
    assert len(d['key_id_long']) >= 20
    param = b''.join((CV25519_OID, struct.pack('>BBBBB', pk_algo_id, 3, 1, kdf_digest_algo, kek_cipher_algo), b'Anonymous Sender    ', d['key_id_long'][:20]))
    # Z_len = the key size for the KEK_alg_ID used with AESKeyWrap;
    # Z = KDF( S, Z_len, Param );
    # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-13.4
    keytable = gpgs.new_hash(kdf_hash, b''.join((b'\0\0\0\1', s, param)), is_slow_hash).digest()[:keytable_size]
    if len(keytable) < keytable_size:
      raise ValueError('Digest %s output is too short for cipher %s.' % (kdf_hash, gpgs.CIPHER_ALGOS[kek_cipher_algo]))
    # C = AESKeyWrap( Z, m ) as per [RFC3394];
    c = aes_key_wrap(keytable, data, is_slow_cipher)
    return struct.pack('>Hc32sB', 263, b'\x40', v_pk, len(c)) + c
  else:
    raise ValueError('Unknown PKESK pk_algo: %r' % (pk_algo,))
  bit_size = n[0]
  size = bit_size >> 3
  random_size = size - 5 - len(session_key)
  if random_size < 0:
    ValueError('Session key too long.')
  random_data = b''
  while len(random_data) < random_size:
    random_data += gpgs.get_random_bytes_default(random_size - len(random_data)).replace(b'\0', b'')
  data = struct.pack('>B%dsxB%dsH' % (len(random_data), len(session_key)), 2, random_data, cipher_algo, session_key, checksum)
  assert len(data) == size
  m = int_from_bytes_be(data)
  del data
  if pk_algo == 1:  # RSA.
    n, e = int_from_bytes_be(n[1]), int_from_bytes_be(d['e'][1])
    return build_mpi(pow(m, e, n), bit_size)
  elif pk_algo == 16:  # Elgamal.
    p, g, y = int_from_bytes_be(n[1]), int_from_bytes_be(d['g'][1]), int_from_bytes_be(d['y'][1])
    p1, k = p - 1, 0
    while not 0 < k < p1:  # Generate a random k: 1 <= k <= p - 2.
      rlong = gpgs.get_random_bytes_default(bit_size >> 3)
      if bit_size & 7:
        rlong = struct.pack('B', ord(gpgs.get_random_bytes_default(1)) & ((1 << (bit_size & 7)) - 1)) + rlong
      k = int_from_bytes_be(rlong)
    # This is noticeaby slower than RSA, because for RSA the exponent e is
    # typically small (0x10001).
    return build_mpi(pow(g, k, p), bit_size) + build_mpi(m * pow(y, k, p) % p, bit_size)
  else:
    assert 0, 'Impossible pk_algo.'


if b'\0'[0]:  # Python 2.7.
  ordx = ord
else:
  ordx = lambda b: b


def parse_subpackets(d, data, i, j):
  while i < j:
    b = ord(data[i : i + 1])
    if b < 192:
      size = b
      i += 1
    elif b < 255:
      size = ((b - 192) << 8 | ord(data[i + 1 : i + 2])) + 192
      i += 2
    else:
      size, = struct.unpack('>L', data[i + 1 : i + 5])
      i += 5
    if not size:
      raise ValueError('Subpacket size must be positive.')
    subpacket_type = ord(data[i : i + 1])
    i += 1
    size -= 1
    #import sys; sys.stderr.write('subpacket type=%d size=%d\n' % (subpacket_type, size))
    if i + size > j:  # TODO(pts): Also check earlier.
      raise ValueError('Subpacket too long.')
    if subpacket_type == 11:  # Preferred cipher_algos.
      d['cipher_algos'] = tuple(ordx(c) for c in data[i : i + size] if ordx(c) in gpgs.CIPHER_ALGOS)
    elif subpacket_type == 21:  # Preferred digest_algos.
      d['digest_algos'] = tuple(ordx(c) for c in data[i : i + size] if ordx(c) in gpgs.CIPHER_ALGOS)
    elif subpacket_type == 22:  # Preferred compress_algos.
      d['compress_algos'] = tuple(ordx(c) for c in data[i : i + size] if ordx(c) in gpgs.CIPHER_ALGOS)
    elif subpacket_type == 27:  # Key flags.
      if size >= 8:
        d['key_flags'], = struct.unpack('<Q', data[i : i + 8])
      else:
        d['key_flags'], = struct.unpack('<Q', data[i : i + size] + b'\0' * (8 - size))
    i += size


def yield_pk_encryption_keys(fread, is_slow_hash):
  # This can load output of `gpg --export' and `gpg --export-secret-key'
  # (with our without --armor), and also ~/.gnupg/pubring.gpg.
  # packet_types for PUBLIC KEY BLOCK: 6, 13, 2, 14, 2.
  # packet_types for longer PUBLIC KEY BLOCK: 6, (13, 2+)+, (17, 2+)+, (14, 2+)+
  #   6: Public Key (provides signature services)
  #   13: User ID (contains single string with real name, comment and e-mail address).
  #   2: Signature (applies to the preceding User ID, User Attribute or Public Subkey)
  #   17: User Attribute (similar to User ID, can contain images as well)
  #   14: Public Subkey (provides encryption services)
  # packet_types for PRIVATE KEY BLOCK: 5, 13, 2, 7, 2.
  d = {}
  for packet_type, is_partial, data in gpgs.yield_gpg_packets(
      fread, armor_types=(b'PUBLIC KEY BLOCK', b'PRIVATE KEY BLOCK'), allowed_first_packet_types=(6, 5)):
    if is_partial:
      raise ValueError('Unexpected partial packet.')
    if packet_type == 13:
      # Example user ID: 'Real Name 2 (Comment 2) <testemail2@email.com>'
      d['user_id'] = ensure_str(data)
    if packet_type == 2 and data[:1] == b'\4':  # Version 4 signature packet, with algo preferences.
      i = 4
      if i + 2 > len(data):
        raise ValueError('Hashed subpacket size too short.')
      size, = struct.unpack('>H', data[i : i + 2])
      i += 2
      if i + size > len(data):
        raise ValueError('Hashed subpacket data too short.')
      parse_subpackets(d, data, i, i + size)
      i += size
      if i + 2 > len(data):
        raise ValueError('Unhashed subpacket size too short.')
      size, = struct.unpack('>H', data[i : i + 2])
      i += 2
      if i + size > len(data):
        raise ValueError('Unhashed subpacket data too short.')
      parse_subpackets(d, data, i, i + size)
    elif packet_type in (6, 14, 5, 7):
      if d:
        yield d
      d = {}
      version = ord(data[:1] or b'\0')
      if len(data) >= 10 and version in (2, 3):
        pk_algo, i = ord(data[7 : 8]), 8
        d['pk_algo'] = pk_algo
      elif len(data) >= 8 and version == 4:
        pk_algo, i = ord(data[5 : 6]), 6
        d['pk_algo'] = pk_algo
      elif len(data) >= 12 and version == 5:  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.5.2
        pk_algo, pk_size = struct.unpack('>BL', data[5 : 10])
        if pk_size < 2:
          raise ValueError('Version 5 key too short.')
        d['pk_algo'], i, data = pk_algo, 10, buffer(data, 0, 10 + pk_size)
      elif version > 5:
        pk_algo = i = 0
      else:
        raise ValueError('Key too short.')
      d['version'], d['key_id'], j = version, None, 0
      data = buffer(data)
      if i:
        if d['pk_algo'] == 1:
          d['pk_algo_str'] = 'RSA'
          (d['n'], d['e']), j = parse_mpis(2, data, i)
          if d['n'][0] < 64:
            raise ValueError('RSA key too short.')
        elif d['pk_algo'] == 16:
          d['pk_algo_str'] = 'Elgamal'
          (d['p'], d['g'], d['y']), j = parse_mpis(3, data, i)
        elif d['pk_algo'] == 18 and data[i : i + 11] == CV25519_OID:
          (pk,), j = parse_mpis(1, data, i + 11)
          kdfp, j = parse_pstring(data, j)
          if len(kdfp) >= 3 and kdfp[:1] == b'\1':
            if pk[0] != 263 or len(pk[1]) != 33 or pk[1][:1] != b'\x40':
              raise ValueError('Invalid CV25519 public key: %s %s' % (pk[0], to_hex_str(pk[1])))
            d['pk'], d['kdfp'] = (pk[1][1:], kdfp[1:]) # (public_key, key_derivation_function_parameters).
            # OpenPGP stores scalars (secret keys) as MPI (big endian), and
            # curve points (public keys) as MPI of big endian(b'\x40' +
            # x_little_endian). curve25519_donna_scalarmult operates on
            # little-endian strings. Thus:
            #
            #   assert b'\x40' + curve25519_donna_scalarmult(parse_mpis(1, secret_key)[0][::-1]) == parse_mpis(1, data, i + 11)[1]
            #
            # We use the [::-1] to convert from big endian to little endian.
          else:
            version = 0  # Ignore this key.
        if version in (2, 3) and d['pk_algo'] == 1:  # RSA.
          d['key_id'] = ensure_str(binascii.hexlify(struct.pack('>Q', d['n'][1][-8:])).upper())
        elif version == 4:
          fp_obj = gpgs.new_hash('sha1', struct.pack('>BH', 0x99, j), is_slow_hash)
          fp_obj.update(data[:j])
          d['key_id_long'] = fp_obj.digest()
          d['key_id'] = to_hex_str(d['key_id_long'][-8:]).upper()
        elif version == 5:  # Untested, GPG 2.2.29 can't generate such a key.
          fp_obj = gpgs.new_hash('sha256', struct.pack('>BL', 0x9a, len(data)), is_slow_hash)
          fp_obj.update(data)
          d['key_id_long'] = fp_obj.digest()
          d['key_id'] = to_hex_str(d['key_id_long'][:8]).upper()
      if not d['key_id']:
        d.pop('key_id', None)
  if d:
    yield d


def load_pk_encryption_key(fread, is_slow_hash):
  pk_encryption_keys, bad_count = [], 0
  #fread = open('/home/pts/.gnupg/pubring.gpg', 'rb').read
  for d in yield_pk_encryption_keys(fread, is_slow_hash):
    if d.get('key_id') and d.get('key_flags', 0xc) & 0xc:  # Encryption.
      pk_encryption_keys.append(d)
    else:
      bad_count += 1
  if not pk_encryption_keys:
    if bad_count:
      raise ValueError('Public-key encryption keys not recognized.')
    else:
      raise ValueError('Public-key encryption keys missing.')
  # Use the last encryption subkey. Typically this is the one which expires
  # the latest. This is the same as what GPG 2.1.18 is doing if 2 never-expiring
  # encryption subkeys are created.
  #
  # TODO(pts): If there is a non-expired subkey, ignore those subkeys which
  # have already expired.
  return pk_encryption_keys[-1]
  #if len(pk_encryption_keys) > 1:
  #  raise ValueError('Multiple public-key encryption keys found: %d' % len(pk_encryption_keys))
