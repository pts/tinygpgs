tinygpgs: symmetric key encryption compatible with GPG in Python
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tinygpgs is a fast library and standalone Python 2 script for doing
symmetric key (passphrase-based) encryption and decryption using the OpenPGP
file format compatible with GPG (GnuPG).

Usage:

  $ ./tinygpgs -c FILE.bin                  # Encrypt.
  $ ./tinygpgs -d <FILE.bin.gpg >FILE2.bin  # Decrypt.
  $ cmp FILE.bin FILE2.bin

Features:

* fast: decrypts <1.26 times slower than gpg(1), and encrypts <1.37 times
  slower than gpg(1), see section ``Speed'' below.
* all ciphers and hashes: supports all ciphers and hashes in the OpenPGP
  spec, including those which PyCrypo doesn't support.
* small, constant memory usage: code + bzip2 decompression dictionary
  and output buffer (can be serveral MiBs) + <128 KiB buffers.
* interoperability: both encryption and decryption works with files to and
  from gpg(1), checked versions 1.0.6, 1.4.1, 1.4.18, 2.1.18, 2.2.17.
* tool compatibility: command-line flags compatible with gpg(1), moslty
  with the same defaults.
* minimal dependencies: Works out-of-the-box with standard Python modules,
  but becomes much faster if PyCrypto is installed.
* any Python 2: works with any Python 2.4, 2.5, 2.6 or 2.7.
* no regexps: the implementation doesn't use regexps, thus avoiding speed
  (and potential catastrophic speed) issues
* binary mode: always works in binary mode, doesn't do any coversion on
  the plaintext (not even when decrypting, this is a difference from GPG)

Planned features:

* encryption: Make it more configurable with command-line flags,
  as a replacement of `gpg --symmetric' == `gpg -c'.
* Python 3: Make it work with Python >=3.5 (e.g. Debian 9) as well, keeping
  Python 2 compatibility.
* docs: Add documentation and help.
* Python library: Upload it to PyPI, make `pip install tinygpgs' work.

Explicit non-features:

* asymmetric (public key) encryption
* asymmetric (public key) signing
* gpg-agent support (e.g. storing passphrases in the agent)
* key management: ~/.gnupg/pubring.gpg and ~/.gnupg/secring.pgp
* asymmetric key (keypair) generation
* trust model

Dependencies:

* Python 2.4, 2.5, 2.6 or 2.7. It currently doesn't work with Python 3.
* Optionally, PyCrypto for fast encryption and decryption. If PyCrypto is
  not available, embedded fallback pure Python code is used instead, but
  that can be >400 times slower than PyCrypto.
* Optionally, hashlib with OpenSSL for fast hashes (string-to-key and
  modification detection). If hashlib isn't available (or it doesn't
  support the hash needed), embedded fallback pure Python code is used
  instead, but that can be >400 times slower (~162 times for SHA-1)
  than hashlib with OpenSSL.
* Only for zip and zlib (de)compression, the standard Python module zip.
* Only dor bzip2 (de)compression, the standard Python module bzip2.
* Only for interactive passphrase prompts, the standard Python module
  getpass. (Use --passphrase or similar to avoid the prompt.)

tinygpgs is free software released under the MIT license. There is NO
WARRANTY. Use at your risk.

Default encryption settings:

* (These settings are the same as GPG 1.0.6 (2001-06-01) ... 1.4.18, unless
  otherwise noted. Also checked GPG 2.2.17 (2019-07-09).)
* --cipher-algo cast5 (Changed in GPG 2.1 (2017-08-09) to aes-128 (according
  to https://en.wikipedia.org/wiki/GNU_Privacy_Guard), and in GPG 2.2
  (2017-09-19) to aes-256. tinygpgs doesn't reflect these changes.)
* --digest-algo sha1
* --s2k-count 65536 (Changed in GPG 2.1 to 3014656 and then to even higher
  values. It makes dictionary attacks properotionally slower.
  tinygpgs doesn't reflect this change.)
* --compress-algo zip
* --compress-level 6
* --force-mdc (The default of GPG depends on other flags.)
* --no-armor

Tools for decrypting symmetric key GPG message
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* gpg1: gpg -d <FILE.bin.gpg >FILE.bin
* gpg2: gpg -d --pinentry-mode loopback <FILE.bin.gpg >FILE.bin
* pgpy: python -c 'import getpass, sys, pgpy; sys.stdout.write(pgpy.PGPMessage.from_file(sys.argv[1]).decrypt(getpass.getpass("Enter passphrase: ")).message)' FILE.bin.gpg >FILE.bin
  installation: pip install pgpy  # Has lots of dependendes, use virtualenv.

https://github.com/thenoviceoof/encryptedfile supports only encryption,
--no-armor, --no-mdc and `--compress-algo none'.

Some other Python PGP projects are listed here: https://pypi.org/project/py-pgp/

GPG symmetric key encryption steps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GPG (and OpenPGP) does the following for encryption:

1. Generates a random 8-byte salt1 and a random salt2 (of the same size as
   the cipher block size).
2. Computes the session key from the passphrase by computing a hash
   (typically SHA-1) of a (configurably) long repeat of the (salt1 +
   passphrase). This has similar purpose as of PBKDF2, but the actual
   algorithm is very different.
3. Optionally compresses the plaintext (with zip, zlib or bzip2).
4. Optionally computes the SHA-1 hash (20 bytes) of the compressed plaintext,
   and appends it.
5. Encrypts the result with a block cipher (CAST5 or AES by default) in CFB
   mode, with a random salt2 of 8 or 16 bytes (same as the cipher block size),
   repeating 2 bytes of the salt2 in the ciphertext, so that an incorrect
   passphrase can be detected at decryption time with high probability.
6. Splits the compressed output to packets with fixed payload size (typically
   8192 bytes).
7. Adds a header.
8. Optionally converts the binary output to Base64 (ASCII), and adds a header
   (-----BEGIN PGP MESSAGE-----).

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
there is a bit less effective, it uses the PyCrypto cipher objects in
MODE_ECB, it's <1.37 times slower than GPG. The large strxor trick could
make it just <1.21 times slower, but its output is incorrect: we need many
calls to strxor in a feedback for MODE_ECB encryption.

There is a class API (GpgSymmetricFile*), which is a <1.11 times slower than
the function-based API (used for the command-line as well) for decryption,
and about the same speed for encryption. Both APIs have the same, very small
memory usage. They share about half of their code. In the benchmarks, the
function-based API is measured, unless otherwise indicated.

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
  $ time python2.7 tinygpgs -d --passphrase abc <hellow5long.bin.gpg >hellow5long.out
  3.980s user

  With standard OpenSSL hashlib + PyCrypto, using the GpgSymmetricFileReader
  file class API.
  $ time python2.7 tinygpgs -d --passphrase abc <hellow5long.bin.gpg >hellow5long.out
  4.388s user

  Old, slow tinygpgs, before the commit ``added speedup for the critical,
  common decryption path'':
  $ time python2.7 tinygpgs -d --passphrase abc <hellow5long.bin.gpg >hellow5long.out
  109.692s user

  pgpy: This is very slow.
  $ python -c 'import getpass, sys, pgpy; sys.stdout.write(pgpy.PGPMessage.from_file(sys.argv[1]).decrypt(getpass.getpass("Enter passphrase: ")).message)' hellow5long.bin.gpg >hellow5long.out
  282.272s
  Also it keeps the entire input and output files in memory, using more than
  1.4 times memory than input_size + output_size.

Encryption (and compression) benchmark measurements on Linux amd64, Debian
9.4:

  <FAST-ENCRYPTION> with standard OpenSSL hashlib + PyCrypto, default.
  $ time python2.7 tinygpgs -c --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  8.828s user

  <FAST-ENCRYPTION>, with GpgSymmetricFileWriter file class API.
  $ time python2.7 tinygpgs -c --file-class --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  8.688s user

  <FAST-ENCRYPTION>, with ASCII armor. CRC24 calculation for the ASCII armor
  makes it very slow. Without the CRC24 update (resulting an invalid output
  file), it would take only 13.516s.
  $ time python2.7 tinygpgs -c -a --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=cast5 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=16
  63.236s user

  <FAST-ENCRYPTION>, with GpgSymmetricFileWriter file class API and ASCII armor. CRC24 calculation for the ASCII armor
  makes it very slow. Without the CRC24 update (resulting an invalid output
  file), it would take only 13.516s.
  $ time python2.7 tinygpgs -c -a --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=cast5 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=16
  63.520s user

  <MEDIUM-ENCRYPTION>.
  $ time python2.7 tinygpgs -c --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  18.856s user

  <SLOW-ENCRYPTION>, doesn't use a write buffer.
  $ time python2.7 tinygpgs -c --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  59.988s user

  # Settings equivalent to `tinygpgs -c --cipher-algo aes-256'.
  $ time gpg -c --pinentry-mode loopback --cipher-algo aes-256 --digest-algo sha1 --s2k-count 65536 --compress-algo zip --compress-level 6 --force-mdc --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  6.444s user

  encryptedfile: This is very-very slow.
  $ time python -c 'import encryptedfile; f = encryptedfile.EncryptedFile("hellow5longef.bin.gpg", "abc", encryption_algo=encryptedfile.EncryptedFile.ALGO_AES256); f.write(open("hellow5long.gpg", "wb").read()); f.close()'
  1847.260s user

__END__
