"""GPG-compatible symmetric key encryption and decryption file class API."""

import struct

from tinygpgs import gpgs

from tinygpgs.pyx import check_binary, buffer, xrange, ensure_binary, text_type, callable


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
    for data in it:
      if data:  # Wait for successful init.
        raise ValueError('Expected empty init string.')
      break
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

  __slots__ = ('_f', '_fwrite', '_pbuf', 'write_hint', '_qbuf', '_qsize',
               '_qhc', '_cpre', '_bs', '_ze', '_ze_compress', '_mdc_obj',
               '_mdc_update', '_cfb_encrypt', '_packet_type', '_packet_header',
               '_packet_hc', '_ciphp', 'bufcap', '_abuf', '_asize', '_acrc',
               '_b2a', 'count', 'first_write_hint')

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
    self.bufcap = 1 << buflog2cap
    if self.bufcap % bs:
      raise ValueError('_pbufcap must be divisible by block size %d, got: %d' % (bs, self.bufcap))
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
      self._fwrite(b'-----BEGIN PGP MESSAGE-----\n\n')
    else:
      self._fwrite(header)
      self._abuf, self._asize, self._acrc, self._b2a = (), 0, (), ()
    self.count = 0  # Compatible with EncryptedFile.
    self._qhc = qhc = struct.pack('>B', 224 | buflog2cap)
    self._pbuf, self.write_hint = [b'\xcb' + qhc], self.bufcap  # Plaintext buffer.
    self._qbuf, self._qsize = [first_plaintext_chunk], len(first_plaintext_chunk)
    self.write(literal_header)
    self.count = 0  # Do it again, reset counter after .write above.
    # To avoid some copies, the caller should call f.write(f.write_hint) all
    # the time. After the first call, typically we'll get f.write_hint ==
    # f.bufcap.

  def tell(self):
    return self.count

  def write(self, data):
    """Write binary data bytes, compress on the fly.

    For high, speed, write data in chunks of at least 8192 bytes (preferred:
    65536 bytes). For maximum speed, use encrypt_symmetric_gpg instead.
    """
    if data:
      self._pbuf.append(data)
      self.count += len(data)
      # Canary mechanism: if a KeyboardInterrupt happens between now and the
      # end of the method, then self._pbuf and self.write_hint will not match,
      # and self.close() won't call _done_pbuf. This is good, because
      # self.close() is usually run in a `finally:' block, and we don't want
      # that block to raise an exception, hiding the original exception in
      # self._flush_buf.
      prem = self.write_hint - len(data)
      if prem <= 0:
        self._flush_pbuf(prem)
      else:
        self.write_hint = prem

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
      self._done_pbuf()
    finally:
      self._fwrite = ()
      if self._f:
        self._f.close();
        self._f = ()
      self._qbuf, self._qsize = (), 0
      self._abuf, self._asize, self._acrc, self._b2a = (), 0, (), ()
      self._cpre = ()
      self._mdc_obj = self._mdc_update = self._ze = self._cfb_encrypt = ()
      self._qhc = self._packet_header = None

  def _done_pbuf(self, _pack=struct.pack, _crc24=gpgs.crc24, _glnph=gpgs.get_last_nonpartial_packet_header):
    # Further .write()s will fail on tuple.append.
    pbuf, prem, self._pbuf, self.write_hint, _bufcap = self._pbuf, self.write_hint, (), 0, self.bufcap
    if not pbuf:
      return  # Canary not found, don't flush.
    lda = sum(len(s) for s in pbuf) - len(pbuf[0])
    if prem != _bufcap - lda:
      return  # Canary not found, don't flush.
    pbuf[0] = _glnph(lda, len(pbuf[0]) > 1 and 11)
    pbuf = b''.join(pbuf)
    qbuf, qsize = self._qbuf, self._qsize
    qbuf.append(self._ze_compress(pbuf))
    del pbuf  # Save memory.
    qsize += len(qbuf[-1])
    if self._ze:
      qbuf.append(self._ze.flush())
      qsize += len(qbuf[-1])
      self._ze = ()
    if self._mdc_obj:
      qbuf.append(b'\xd3\x14')
      qsize += 2
    data = b''.join(qbuf)
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
      self._add_encrypted(self._cfb_encrypt(data[j:] + b'\0' * (self._bs - ldbs))[:ldbs])
    data = self._cpre  # Flush the last encrypted partial packet.
    self._cpre = ()
    header = _glnph(len(data), self._ciphp and self._packet_type)
    fwrite = self._fwrite
    if self._b2a:
      abuf, asize, acrc, _b2a = self._abuf, self._asize, self._acrc, self._b2a
      self._abuf, self._asize, self._acrc, self._b2a = (), 0, (), ()
      acrc = _crc24(data, _crc24(header, acrc))
      abuf.append(header)
      abuf.append(data)
      asize += len(header) + len(data)
      adata, lam = b''.join(abuf), asize % 48
      assert len(adata) == asize
      lal, _buffer = asize - lam, buffer
      for i in xrange(0, lal, 48):
        fwrite(_b2a(_buffer(adata, i, 48)))  # Contains trailing b'\n'.
      abuf[:] = (adata[lal:],)
      adata, asize = (), lam
      fwrite(gpgs.get_gpg_armor_trailer(abuf, asize, acrc, _b2a))
    else:
      fwrite(header)
      fwrite(data)

  def _flush_pbuf(self, prem, _pack=struct.pack, _buffer=buffer):
    if prem <= 0:
      pbuf, qbuf, ze_compress, _bufcap, qhc = self._pbuf, self._qbuf, self._ze_compress, self.bufcap, self._qhc
      if not prem:
        # Avoiding this long copy and doing `for data in pbuf:' instead
        # makes it a bit slower with bufcap == 8192. That's probably because
        # calling ze_compress twice is slow.
        data = b''.join(pbuf)  # Long copy.
        assert prem == _bufcap - len(data) + len(pbuf[0])  # Consistency.
        dataq = ze_compress(data)
        if dataq:
          qbuf.append(dataq)
          self._qsize += len(dataq)
        if self._qsize >= _bufcap:
          self._flush_qbuf()
        pbuf[:] = (qhc,)
        self.write_hint = _bufcap  # Must be last for canary.
      elif prem > -_bufcap:  # This is just speedup, could be commented out.
        data = b''.join(pbuf)
        assert prem == _bufcap - len(data) + len(pbuf[0])  # Consistency.
        dataq = ze_compress(data[:prem])  # This doesn't work if prem == 0.
        if dataq:
          qbuf.append(dataq)
          self._qsize += len(dataq)
        if self._qsize >= _bufcap:
          self._flush_qbuf()
        pbuf[:] = (qhc, data[prem:])  # Long copy. It doesn't work if prem == 0.
        self.write_hint = prem + _bufcap  # Must be last for canary.
      else:
        lda = sum(len(s) for s in pbuf) - len(pbuf[0])
        assert prem == _bufcap - lda  # Consistency.
        ldam = lda % _bufcap
        #assert lda >= (_bufcap << 1)  # Follows from `prem > -_bufcap'.
        datap = pbuf.pop()
        i = _bufcap - (lda - len(datap))
        assert 0 < i < _bufcap  # Only last one is too long.
        #assert len(datap) - ldam - i == lda - _bufcap - ldam  # True but slow.
        #assert not (len(datap) - ldam - i) % _bufcap  # True but slow.
        pbuf.append(datap[:i])
        dataq = b''.join(pbuf)
        assert len(dataq) - len(pbuf[0]) == _bufcap  # Consistency.
        dataq = ze_compress(dataq)
        if dataq:
          qbuf.append(dataq)
          self._qsize += len(dataq)
        if self._qsize >= _bufcap:
          self._flush_qbuf()
        for i in xrange(i, len(datap) - ldam, _bufcap):
          dataq = ze_compress(qhc)
          if dataq:
            qbuf.append(dataq)
            self._qsize += len(dataq)
          dataq = ze_compress(_buffer(datap, i, _bufcap))
          if dataq:
            qbuf.append(dataq)
            self._qsize += len(dataq)
          if self._qsize >= _bufcap:
            self._flush_qbuf()
        if ldam:
          pbuf[:] = (qhc, datap[-ldam:])  # Long copy, unavoidable.
          self.write_hint = _bufcap - ldam  # Must be last for canary.
        else:
          pbuf[:] = (qhc,)
          self.write_hint = _bufcap  # Must be last for canary.

  def _flush_qbuf(self):
    qbuf = self._qbuf
    data = b''.join(qbuf)
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
    cpre, _b2a, _bufcap, fwrite = self._cpre, self._b2a, self.bufcap, self._fwrite
    cpre += cdata  # Long copy. TODO(pts): Avoid it with multiple writes.
    del cdata
    lcpb = len(cpre) - len(cpre) % _bufcap
    #if lcpb < _bufcap:  # May happen only if called from .close().
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
          adata, lam = b''.join(abuf), asize % 48
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
  in https://pypi.org/project/encryptedfile/ , version 1.1.1, but it's much faster.

  Example usage:

    import getpass
    f = EncryptedFile('FILE.bin.gpg', mode='wb', passphrase=getpass.getpass())
    try:
      f.write('Hello, World!\n')
      f.write('This is the end.\n')
    finally:
      f.close()

  This class implements newline conversion by default (mode='w', there is
  no 'b' in it). If you don't need that, you should use the
  GpgSymmetricFileWriter class instead, it's even faster than this
  EncryptedFile.

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
      HASH_MD5: lambda data=b'': new_hash('md5', data),
      HASH_SHA1: lambda data=b'': new_hash('sha1', data),
      HASH_RIPEMD160: lambda data='': new_hash('ripemd160', data),
      HASH_SHA256: lambda data=b'': new_hash('sha256', data),
      HASH_SHA384: lambda data=b'': new_hash('sha384', data),
      HASH_SHA512: lambda data=b'': new_hash('sha512', data),
      HASH_SHA224: lambda data=b'': new_hash('sha224', data),
  }

  __slots__ = ('file', '_is_text', '_prefix')

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
        'iv': check_binary(iv),
        'salt': check_binary(salt),
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
    self._prefix = ''
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
    write_func = self.write
    for line in lines:
      write_func(line)

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
    if self._is_text and self._prefix:
      assert self._prefix == b'\r'
      GpgSymmetricFileWriter.write(self, b'\r\n')
    GpgSymmetricFileWriter.close(self)
    if self.file:
      self.file.close()

  def write(self, data):
    """Write text bytes, converting it to binary first.

    This method was added for compatibility with encrytedfile, it's added
    functionality is used instead of .write for non-binary mode.
    """
    if self._is_text:
      if isinstance(data, text_type):
        data = ensure_binary(data)
      data, self._prefix = self._prefix + data, ''
      if data:
        if data[-1:] == b'\r':
          data, self._prefix = data[:-1], b'\r'
        # This is a simple, low-effort, but correct conversion of line breaks to '\r\n',
        # without using regexps.
        data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n').replace(b'\n', b'\r\n')
    GpgSymmetricFileWriter.write(self, data)
