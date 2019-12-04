"""GPG-compatible symmetric key encryption and decryption file class API."""

import struct

from tinygpgs import gpgs


class GpgSymmetricFileReader(object):
  """File-like object with .read() method for decrypting symmetric GPG.

  Example usage:

    import getpass
    f = GpgSymmetricFileReader('FILE.bin.gpg', 'rb', getpass.getpass())
    try:
      print(f.read())  # Use f.read(8192) to limit memory usage.
    finally:
      f.close()

  GpgSymmetricFileReader is able to decrypt files encrypted with GPG
  symmetric key encryption (passphrase, secret key), conforming to the
  OpenPGP file format (RFC 4880, e.g. created with GnuPG gpg(1) or pgp(1).

  GpgSymmetricFileReader isn't able to decrypt files encrypted with GPG
  public-key encryption.

  If the file has a signature, GpgSymmetricFileReader silently ignores (and
  doesn't validate) the signature.

  GpgSymmetricFileReader uses very little memomry (128 KiB + bzip2
  dictionay and decompression buffers).

  GpgSymmetricFileReader is not thread-safe, don't use it from multiple
  threads at the same time.

  If you need something very fast, use decrypt_symmetric_gpg
  instead of this object.
  """

  __slots__ = ('read', '_f')

  def __init__(self, filename, mode, *args, **kwargs):
    """Also pass passphrase=... You can pass .read method as filename."""
    if mode not in ('r', 'rb', 'br'):
      raise ValueError('Bad mode for GpgSymmetricFileReader: %s' % (mode,))
    if callable(filename):
      self._f, fread = None, filename
    else:
      self._f = f = open(filename, 'rb')
      fread = f.read
    fread = gpgs.get_decrypt_symmetric_gpg_literal_packet_reader(
        fread, *args, **kwargs)
    # TODO(pts): Add has_mdc, cipher_algo etc. and other parameters to self,
    # make them available for inspection. Also in *FileWriter.
    it = gpgs.yield_gpg_literal_data_chunks(fread)
    if it.next():  # Wait for successful init.
      raise ValueError('Expected empty init string.')
    # TODO(pts): Flush before raising an exception (on e.g. MDC mismatch),
    # modify iter_to_fread_or_all.
    self.read = gpgs.iter_to_fread_or_all(it)

  def close(self):
    self.read = ()
    if self._f:
      self._f.close();
      self._f = ()


class GpgSymmetricFileWriter(object):
  """File-like object with .write() method for encrypting symmetric GPG.

  Example usage:

    import getpass
    f = GpgSymmetricFileWriter('FILE.bin.gpg', 'wb', getpass.getpass())
    try:
      f.write('Hello, World!\n')
      f.write('This is the end.\n')
    finally:
      f.close()

  GpgSymmetricFileWriter encrypts the content written to it using symmetric
  key encryption (passphrase, secret key), conforming to the OpenPGP file
  format (RFC 4880), and gpg(1) (and probably pgp(1)) will be able to
  decrypt it.

  GpgSymmetricFileWriter doesn't support public-key encryption or public-key
  signing (with the private key).

  GpgSymmetricFileWriter uses very little memomry (128 KiB + bzip2
  dictionay and decompression buffers).

  GpgSymmetricFileWriter is not thread-safe, don't use it from multiple
  threads at the same time.

  If you need something very fast, use encrypt_symmetric_gpg instead of this
  object.
  """

  __slots__ = ('_f', '_fwrite', '_pbuf', '_psize', '_plitp', '_qbuf', '_qsize',
               '_qhc', '_cpre', '_bs', '_ze', '_ze_compress', '_mdc_obj',
               '_mdc_update', '_cfb_encrypt', '_packet_type', '_packet_header',
               '_packet_hc', '_ciphp', '_bufcap', '_abuf', '_asize', '_acrc',
               '_b2a', '_psizec', 'count')

  def __init__(self, filename, mode, *args, **kwargs):
    """Also pass passphrase=... You can pass .write method as filename."""
    mode2 = mode.replace('b', '')
    if mode2 not in ('w', 'a'):
      raise ValueError('Bad mode for GpgSymmetricFileWriter: %s' % (mode,))
    if callable(filename):
      self._f, self._fwrite = None, filename
    else:
      self._f = f = open(filename, mode2 + 'b')
      self._fwrite = f.write
    (header, encrypt_func, bs, cfb_encrypt, plaintext_salt, mdc_obj, mdc_update,
     first_plaintext_chunk, ze, packet_type, packet_header, fr, literal_header,
     buflog2cap, do_add_ascii_armor,
    ) = gpgs.get_encrypt_symmetric_gpg_params(*args, **kwargs)
    self._bs, self._ze, self._mdc_obj, self._packet_type, self._packet_header = bs, ze, mdc_obj, packet_type, packet_header
    self._cpre, self._packet_hc, self._ciphp = packet_header, struct.pack('>B', 192 | packet_type), True  # Ciphertext buffer.
    self._cfb_encrypt = cfb_encrypt or gpgs.get_cfb_encrypt_func(encrypt_func, bs, fr)  # Slow, but works without PyCrypto.
    self._bufcap = 1 << buflog2cap
    if self._bufcap % bs:
      raise ValueError('_pbufcap must be divisible by block size %d, got: %d' % (bs, self._bufcap))
    if mdc_obj:
      self._mdc_update = mdc_obj.update
    else:
      self._mdc_update = lambda data: 0
    if ze:
      self._ze_compress = ze.compress
    else:
      self._ze_compress = lambda data: data[:]
    if do_add_ascii_armor:
      import binascii
      self._abuf, self._asize, self._acrc, self._b2a = [header], len(header), gpgs.crc24(header), binascii.b2a_base64
      assert self._b2a  # Used in tests later.
      # Just like in encrypt_symmetric_gpg(...), we treat all output files as
      # binary, using '\n' as line separator. This is by design and for
      # simplicity.
      self._fwrite('-----BEGIN PGP MESSAGE-----\n\n')
    else:
      self._fwrite(header)
      self._abuf, self._asize, self._acrc, self._b2a = (), 0, (), ()
    self.count = 0  # Compatible with EncryptedFile.
    self._pbuf, self._psize, self._plitp = [literal_header], len(literal_header), True  # Plaintext buffer.
    self._psizec = self._psize  # Canary used in .close() to detect a partial .write().
    self._qhc = struct.pack('>B', 224 | buflog2cap)
    self._qbuf, self._qsize = [first_plaintext_chunk], len(first_plaintext_chunk)
    self._flush_pbuf()
    del header

  def tell(self):
    return self.count

  def write(self, data):
    """Write binary data bytes, compress on the fly.

    For high, speed, write data in chunks of at least 8192 bytes (preferred:
    65536 bytes). For maximum speed, use encrypt_symmetric_gpg instead.
    """
    if data:
      self._psizec = psize = self._psize
      self.count += len(data)
      # If a KeyboardInterrupt happens between now and setting of
      # self._psizec below, then `self._psize == self._psizec' will be fals
      # in self.close().
      self._psize = psize + len(data)
      self._pbuf.append(data)
      if self._psize > self._bufcap:
        self._flush_pbuf()
      self._psizec = self._psize

  def flush(self):
    """Flushes the backing file object.

    It's impossible to flush the encryption buffer, because partial GPG
    packets can't be flushed early, because they have a fixed buffer size
    (of a power of 2).
    """
    if self._f:
      self._f.flush()

  def close(self):
    """Closes the file, flushing all data."""
    # .close() is not suitable as __del__, it refers to global variables.
    try:
      if self._psize == self._psizec:
        self._done_pbuf()
    finally:
      self._fwrite = ()
      if self._f:
        self._f.close();
        self._f = ()
      self._pbuf, self._psize = (), 0  # Further .write()s will fail.
      self._qbuf, self._qsize = (), 0
      self._abuf, self._asize, self._acrc, self._b2a = (), 0, (), ()
      self._cpre = ()
      self._mdc_obj = self._mdc_update = self._ze = self._cfb_encrypt = ()
      self._plitp = self._qhc = self._packet_header = None

  def _done_pbuf(self, _pack=struct.pack, _crc24=gpgs.crc24, _glnph=gpgs.get_last_nonpartial_packet_header):
    self._psizec = ()  # Ruin the canary to prevent .close() from calling again.
    pbuf, psize = self._pbuf, self._psize
    if pbuf is ():
      raise ValueError('Duplicate call to _done_pbuf.')
    if pbuf:
      self._flush_pbuf()
    data = ''.join(pbuf)
    assert len(data) == psize
    self._pbuf, pbuf, self._psize = (), (), 0
    pbufx = _glnph(len(data), self._plitp and 11)
    qbuf, qsize = self._qbuf, self._qsize
    qbuf.append(self._ze_compress(pbufx))
    qbuf.append(self._ze_compress(data))
    qsize += len(qbuf[-2]) + len(qbuf[-1])
    if self._ze:
      qbuf.append(self._ze.flush())
      qsize += len(qbuf[-1])
      self._ze = ()
    if self._mdc_obj:
      qbuf.append('\xd3\x14')
      qsize += 2
    data = ''.join(qbuf)
    assert len(data) == qsize
    self._qbuf, qbuf, self._qsize = (), (), 0  # Further .write()s will fail.
    if self._mdc_obj:
      self._mdc_update(data)
      data += self._mdc_obj.digest()  # Long copy, once.
      self._mdc_obj = ()
    self._mdc_update = ()
    ldbs = len(data) % self._bs
    j = len(data) - ldbs
    if j:
      self._add_encrypted(self._cfb_encrypt(buffer(data, 0, j)))
    if ldbs:  # Encrypt the last partial block.
      self._add_encrypted(self._cfb_encrypt(data[j:] + '\0' * (self._bs - ldbs))[:ldbs])
    data = self._cpre  # Flush the last encrypted partial packet.
    self._cpre = ()
    header = _glnph(len(data), self._ciphp and self._packet_type)
    fwrite = self._fwrite
    if self._b2a:
      abuf, asize, acrc, _b2a = self._abuf, self._asize, self._acrc, self._b2a
      self._abuf, self._asize, self._acrc, self._b2a = (), 0, (), ()
      acrc = crc24(data, crc24(header, acrc))
      abuf.append(header)
      abuf.append(data)
      asize += len(header) + len(data)
      adata, lam = ''.join(abuf), asize % 48
      assert len(adata) == asize
      lal, _buffer = asize - lam, buffer
      for i in xrange(0, lal, 48):
        fwrite(_b2a(_buffer(adata, i, 48)))  # Contains trailing '\n'.
      abuf[:] = (adata[lal:],)
      adata, asize = (), lam
      fwrite(get_gpg_armor_trailer(abuf, asize, acrc, _b2a))
    else:
      fwrite(header)
      fwrite(data)

  def _flush_pbuf(self, _pack=struct.pack, _buffer=buffer):
    _bufcap = self._bufcap
    if self._psize >= _bufcap:
      pbuf, psize, qbuf, ze_compress = self._pbuf, self._psize, self._qbuf, self._ze_compress
      data = ''.join(pbuf)
      assert len(data) == psize
      j = psize - psize % _bufcap
      for i in xrange(0, j, _bufcap):
        # TODO(pts): Is it faster to do additional buffering before compression?
        if self._plitp:
          dataq = ze_compress('\xcb' + self._qhc)  # packet_type == 11.
          self._plitp = False
        else:
          dataq = ze_compress(self._qhc)
        if dataq:
          qbuf.append(dataq)
          self._qsize += len(dataq)
        dataq = ze_compress(_buffer(data, i, _bufcap))
        if dataq:
          qbuf.append(dataq)
          self._qsize += len(dataq)
        if self._qsize >= _bufcap:
          self._flush_qbuf()
      pbuf[:], self._psize = [data[j:]], psize - j  # An empty string is OK here.

  def _flush_qbuf(self):
    qbuf = self._qbuf
    data = ''.join(qbuf)
    if data:
      assert self._qsize == len(data)
      ldbs = len(data) % self._bs
      j = len(data) - ldbs
      if j:
        data2 = buffer(data, 0, j)
        self._mdc_update(data2)
        self._add_encrypted(self._cfb_encrypt(data2))
      if ldbs:
        qbuf[:] = (data[j:],)
      else:
        del qbuf[:]
      self._qsize = ldbs

  def _add_encrypted(self, cdata, _crc24=gpgs.crc24):
    cpre, _b2a, _bufcap, fwrite = self._cpre, self._b2a, self._bufcap, self._fwrite
    cpre += cdata  # Long copy. TODO(pts): Avoid it with multiple writes.
    del cdata
    lcpb = len(cpre) - len(cpre) % _bufcap
    #if lcpb < _bufcap:  # May happen only if called from _done_pbuf.
    if _b2a:
      abuf, asize, acrc, _buffer = self._abuf, self._asize, self._acrc, buffer
      for i in xrange(0, lcpb, _bufcap):  # Usually only once.
        if self._ciphp:
          # TODO(pts): Reset state on fwrite failure (everywhere).
          header = self._packet_hc + self._qhc  # packet_type in (9, 18).
          self._ciphp = False
        else:
          header = self._qhc
        # We copy it to make crc24 faster on Python 2.7.
        data = cpre[i : i + _bufcap]
        acrc = _crc24(data, _crc24(header, acrc))  # Very slow.
        abuf.append(header)
        abuf.append(data)
        asize += len(header) + len(data)
        if asize >= 48:
          adata, lam = ''.join(abuf), asize % 48
          lal = asize - lam
          # We need a loop here so that we get '\n' after each 48 (+16) bytes.
          for i in xrange(0, lal, 48):
            fwrite(_b2a(_buffer(adata, i, 48)))  # Contains trailing '\n'.
          abuf[:] = (adata[lal:],)
          asize = lam
      self._cpre, self._asize, self._acrc = cpre[lcpb:], asize, acrc
    else:
      for i in xrange(0, lcpb, _bufcap):  # Usually only once.
        if self._ciphp:
          # TODO(pts): Reset state on fwrite failure (everywhere).
          fwrite(self._packet_hc + self._qhc)  # packet_type in (9, 18).
          self._ciphp = False
        else:
          fwrite(self._qhc)
        fwrite(buffer(cpre, i, _bufcap))
      self._cpre = cpre[lcpb:]


# --- Unified class API.


def GpgSymmetricFile(filename, mode, *args, **kwargs):
  """Returns file-like object for GPG encryption or decryption.

  Example usage for GPG decryption:

    import getpass
    f = GpgSymmetricFile('FILE.bin.gpg', 'rb', getpass.getpass())
    try:
      print(f.read())  # Use f.read(8192) to limit memory usage.
    finally:
      f.close()

  Example usage for GPG encryption:

    import getpass
    f = GpgSymmetricFile('FILE.bin.gpg', 'wb', getpass.getpass())
    try:
      f.write('Hello, World!\n')
      f.write('This is the end.\n')
    finally:
      f.close()

  See more info in the docstrings of GpgSymmetricFileReader and
  GpgSymmetricFileWriter.
  """
  if 'r' in mode:
    cons = GpgSymmetricFileReader
  else:
    cons = GpgSymmetricFileWriter
  return cons(filename, mode, *args, **kwargs)


# --- EncryptedFile-compatible writer class API.


class EncryptedFile(GpgSymmetricFileWriter):
  """EncryptedFile-compatible class for encrypting symmetric GPG.

  Implements the same interface as class EncryptedFile in EncryptedFile.py
  (https://github.com/thenoviceoof/encryptedfile/blob/master/encryptedfile/EncryptedFile.py)
  in https://pypi.org/project/encryptedfile/ , version 1.1.

  Example usage:

    import getpass
    f = EncryptedFile('FILE.bin.gpg', passphrase=getpass.getpass())
    try:
      f.write('Hello, World!\n')
      f.write('This is the end.\n')
    finally:
      f.close()

  The only incompatibility is with writing line breaks in multiple chunks in
  text mode, e.g. for .write('A\r'), .write('\nB'), the user may be
  expecting 'A\r\nB', but actually 'A\r\r\nB' will be written. To avoid this
  problem, don't include '\r' in the argument to .write(...).
  !! Fix this incompatibility by buffering 1 byte.

  This implementation tries to be compatible with encryptedfile, keeping
  most of its design and behavior intact, and only improving speed.
  """

  __version__ = (1, 1, 1)  # Compatible with encryptedfile 1.1.1.

  # OpenPGP values
  ALGO_IDEA = 1  # Not in encryptedfile 1.1.1
  ALGO_3DES = ALGO_DES3 = 2  # Not in encryptedfile 1.1.1
  ALGO_CAST5 = 3  # Not in encryptedfile 1.1.1
  ALGO_BLOWFISH = 4
  ALGO_AES128 = 7
  ALGO_AES196 = 8
  ALGO_AES256 = 9
  ALGO_TWOFISH = 10  # Not in encryptedfile 1.1.1

  S2K_SIMPLE = 0
  S2K_SALTED = 1
  S2K_ITERATED = 3

  HASH_MD5 = 1
  HASH_SHA1 = 2
  HASH_RIPEMD160 = 3  # Not in encryptedfile 1.1.1
  HASH_SHA256 = 8
  HASH_SHA384 = 9
  HASH_SHA512 = 10
  HASH_SHA224 = 11  # Not in encryptedfile 1.1.1

  # Unused, for compatibility with encryptedfile 1.1.1. In
  # encryptedfile the values are PyCrypto.Cipher.* module objects.
  ENCRYPTION_ALGOS = {
      ALGO_IDEA: 'IDEA',
      ALGO_3DES: '3DES',
      ALGO_BLOWFISH : 'Blowfish',
      ALGO_AES128: 'AES',
      ALGO_AES196: 'AES',
      ALGO_AES256: 'AES',
      ALGO_TWOFISH: 'Twofish',
  }

  KEY_SIZES = dict(gpgs.KEYTABLE_SIZES)

  # Unused, for compatibility with encryptedfile 1.1.1. In
  # encryptedfile the values are hashlib constructor functions.
  HASHES = {
      HASH_MD5: lambda data='': new_hash('md5', data),
      HASH_SHA1: lambda data='': new_hash('sha1', data),
      HASH_RIPEMD160: lambda data='': new_hash('ripemd160', data),
      HASH_SHA256: lambda data='': new_hash('sha256', data),
      HASH_SHA384: lambda data='': new_hash('sha384', data),
      HASH_SHA512: lambda data='': new_hash('sha512', data),
      HASH_SHA224: lambda data='': new_hash('sha224', data),
  }

  __slots__ = ('file', '_is_text')

  def __init__(
      self, file_obj, passphrase, mode='w', iv=None, salt=None,
      block_size=16, buffer_size=1024, timestamp=None,
      encryption_algo=ALGO_AES256, hash_algo=HASH_SHA256,
      key_method=S2K_ITERATED, iterated_count=(16, 6)):
    """Creates a writeable file-like object which encrypts.

    Args:
      file_obj: a string or file-like object: a string should be a path, or
          a file object to write through to the file.
      passphrase: passphrase
      mode: usual file modes
      iv: initialization vector, randomly generated if not
          given, same size as block_size.
      key_method: which S2K_* method to use
      hash_algo: which HASH_* to convert the passphrase with
      encryption_algo: which ALGO_* to encrypt the plaintext with
      block_size: used by the cipher. Ignored, the cipher knows its own block
          size.
      buffer_size: how much data should be slurped up before encrypting
      timestamp: <int>: timestamp, if any, to be attached to the literal data
          if not given, just writes zeroes
      iterated_count: a tuple (base, exp), where base is between [16, 32),
        and the exp is between 6 and 22
    """
    if 'w' not in mode:
      raise ValueError('Only \'wb\' mode supported')
    encrypt_params = {
        'passphrase': passphrase,
        'cipher': gpgs.CIPHER_ALGOS[encryption_algo],
        's2k_digest': gpgs.DIGEST_ALGOS[hash_algo],
        'compress': 'none',
        's2k_mode': key_method,
        's2k_count': iterated_count[0] << iterated_count[1],
        'mtime': timestamp or 0,
        'do_mdc': False,
        'do_add_ascii_armor': False,
        'iv': iv,
        'salt': salt,
    }
    if isinstance(file_obj, basestring):
      if len(file_obj) > 0xff:
        raise ValueError('File name is too long')
      self.file = open(file_obj, mode)
      encrypt_params['plain_filename'] = file_obj
    elif isinstance(file_obj, file):
      self.file = file_obj
      encrypt_params['plain_filename'] = file_obj.name[:0xff]
    else:
      raise TypeError
    del block_size
    buflog2cap = 13  # At least 8192 bytes, for speed.
    while buffer_size > (1 << buflog2cap):
      buflog2cap += 1
    encrypt_params['buflog2cap'] = buflog2cap
    if 'b' in mode:
      encrypt_params['literal_type'], self._is_text = 'b', False
    else:
      encrypt_params['literal_type'], self._is_text = 't', True
    GpgSymmetricFileWriter.__init__(self, self.file.write, mode, **encrypt_params)

  # Handle {with EncryptedFile(...) as f:} notation.
  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    self.close()

  def writelines(self, lines):
    self.write(''.join(lines))

  def read(self, *args, **kwargs):
    raise NotImplementedError()

  def readlines(self, *args, **kwargs):
    raise NotImplementedError()

  def seek(self, offset, whence=None):
    raise NotImplementedError()

  def isatty(self):
    return False

  def flush(self):
    if self.file:
      self.file.flush()

  def close(self):
    if self.file.closed:
      return
    GpgSymmetricFileWriter.close(self)
    if self.file:
      self.file.close()

  def write(self, data):
    """Write text bytes, converting it to binary first.

    This method was added for compatibility with encrytedfile, it's added
    functionality is used instead of .write for non-binary mode.
    """
    if self._is_text:
      if isinstance(data, unicode):
        data = data.encode('utf-8')
      # This is a simple, low-effort conversion of line breaks to '\r\n',
      # without using regexps. It works correctly except for
      # .write_text('A\r'), .write_text('\nB'), for which the user may be
      # expecting 'A\r\nB', but actually 'A\r\r\nB' will be written.
      data = data.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\r\n')
    GpgSymmetricFileWriter.write(self, data)
