tinygpgs: symmetric key encryption tool compatible with GPG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tinygpgs is a Python 2 script for doing symmetric key encryption and
decryption using the OpenPGP file format compatible with GPG (GnuPG).

Usage:

  $ ./tinygpgs -c <FILE.bin >FILE.bin.gpg   # Encrypt.
  $ ./tinygpgs -d <FILE.bin.gpg >FILE2.bin  # Decrypt.
  $ cmp FILE.bin FILE2.bin

Features:

* fast: decrypts <1.26 times slower than gpg(1), and encrypts <2.93 times
  slower than gpg(1), see section ``Speed'' below.
* small, constant memory usage: code + bzip2 decompression dictionary
  and output buffer (can be serveral MiBs) + <128 KiB buffers.
* tool compatibility: command-line flags compatible with gpg(1).
* minimal dependencies: Works out-of-the-box with standard Python modules,
  but becomes much faster if PyCrypto is installed.
* any Python 2: works with any Python 2.4, 2.5, 2.6 or 2.7.

Planned features:

* encryption: Make it more configurable with command-line flags,
  as a replacement of `gpg --symmetric' `gpg -c'.
* Python 3: Make it work with Python >=3.5 as well, keeping Python 2
  compatibility.
* docs: Add documentation and help.
* Python library: Upload it to PyPI, make `pip install tinygpgs' work.

Explicit non-features:

* asymmetric (public key) encryption
* asymmetric (public key) signing
* gpg-agent support
* key management: ~/.gnupg/pubring.gpg and ~/.gnupg/secring.pgp
* asymmetric key generation
* trust model

Tools for decrypting symmetric key GPG message
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* gpg1: gpg -d <FILE.bin.gpg >FILE.bin
* gpg2: gpg -d --pinentry-mode loopback <FILE.bin.gpg >FILE.bin
* pgpy: python -c 'import getpass, sys, pgpy; sys.stdout.write(pgpy.PGPMessage.from_file(sys.argv[1]).decrypt(getpass.getpass("Enter passphrase: ")).message)' FILE.bin.gpg >FILE.bin
  installation: pip install pgpy  # Has lots of dependendes, use virtualenv.

https://github.com/thenoviceoof/encryptedfile supports only encryption,
--no-mdc and `--compress-algo none'.

Speed
~~~~~
For string-to-key conversion, data is grouped to chunks of almost 65536
bytes, and most of the time is spent in hash computation in C extensions,
very little time is spend in Python code. For more details, see <FAST-HASH>
in the source code.

The Python code of critical path of tinygpgs decryption is optimized: it
contains very little Python code, most of the heavly lifting is done by
Crypto.Cipher._AES.new(...).encrypt and Crypto.Util.strxor.strxor with long
strings (partial packet size in the encrypted input, typically 8192 bytes),
both of which are implemented in C extensions. On average, the decryption
part of `tinygpgs -d' is <1.26 slower than gpg(1), see the numbers in the
``Benchmarks'' section. For more details, see <FAST-DECRYPTION> in the
source code.

There is a similar speedup implemented for `tinygpgs -c', see
<FAST-ENCRYPTION> in the source code for more details. The optimization
there is less effective (yielding a <2.93 times slowdown compared to
gpg(1)), because larger strxor buffering is not possible because how the
encryption in CFB mode works. With larget strxor buffering, `tinygpgs -c'
would be only <1.21 times slower than gpg(1). See <BAD-FAST-ENCRYPTION>
in the code for more details.

Benchmarks
~~~~~~~~~~
Encrypted input file (hellow5long.bin.gpg) parameters:

* ~32.1 MiB compressed and encrypted.
* Corresponding plaintext file is 32 MiB of random bytes (uncompressable).
* No encrypted session key.
* --cipher-algo aes-256
* --s2k-mode 3  # iterated-salted
* --s2k-count 3014656
* --hash-algo sha1
* --compress-algo zip
* --force-mdc
* Partial packet are of size 8192.

Decryption (and decompression) benchmark measurements on Linux amd64,
Debian 9.4:

  gpg (GNUPG) 2.1.18.
  $ time gpg2 -d --pinentry-mode loopback <hellow5long.bin.gpg >hellow5long.out
  3.168s user

  With standard OpenSSL hashlib + PyCrypto.
  $ time python2.7 tinygpgs -d abc <hellow5long.bin.gpg >hellow5long.out
  3.980s user

  Old, slow tinygpgs, before the commit ``added speedup for the critical,
  common decryption path'':
  $ time python2.7 tinygpgs -d abc <hellow5long.bin.gpg >hellow5long.out
  109.692s user

  pgpy:
  $ python -c 'import getpass, sys, pgpy; sys.stdout.write(pgpy.PGPMessage.from_file(sys.argv[1]).decrypt(getpass.getpass("Enter passphrase: ")).message)' hellow5long.bin.gpg >hellow5long.out
  282.272s
  Also it keeps the entire input and output files in memory, using more than
  1.4 times memory than input_size + output_size.

Encryption (and compression) benchmark measurements on Linux amd64, Debian
9.4:

  $ time ./tinygpgs -c abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  18.856s user

  This produces incorrect output, but it makes fewer calls to _fast_strxor
  and encrypt_func, thus indicating an estimate on the best possible
  achievable speed in Python:
  $ time ./tinygpgs -c abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  7.860s user

  $ time gpg -c --pinentry-mode loopback --cipher-algo aes-256 --digest-algo sha1 --s2k-count 65536 --compress-algo zip --compress-level 9 --force-mdc <hellow5long.bin >hellowc5long.bin.gpg
  6.444s user

  This is very slow.
  $ time python -c 'import encryptedfile; f = encryptedfile.EncryptedFile("hellow5longef.bin.gpg", "abc", encryption_algo=encryptedfile.EncryptedFile.ALGO_AES256); f.write(open("hellow5long.gpg", "rb").read()); f.close()'
  1847.260s user

Some other Python PGP projects are listed here: https://pypi.org/project/py-pgp/

__END__
