tinygpgs: symmetric key encryption compatible with GPG in Python
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tinygpgs is a fast module and standalone Python script for doing
symmetric key (passphrase-based) encryption and decryption using the OpenPGP
file format compatible with GPG (GnuPG).

Usage:

  $ ./tinygpgs -c FILE.bin                  # Encrypt.
  $ ./tinygpgs -d <FILE.bin.gpg >FILE2.bin  # Decrypt.
  $ cmp FILE.bin FILE2.bin

Features:

* fast: decrypts <1.26 times slower than gpg(1), and encrypts <1.37 times
  slower than gpg(1), see section ``Speed'' below.
* tiny: the full-featured standalone command-line tool is smaller than 50
  KiB (minified and ZIP-compressed), and it contains all the GPG ciphers and
  hashes as Python code
* all ciphers and hashes: supports all ciphers and hashes in the OpenPGP
  spec, including those which PyCrypto doesn't support.
* small, constant memory usage: code + bzip2 decompression dictionary
  and output buffer (can be serveral MiBs) + <128 KiB buffers.
* interoperability: both encryption and decryption works with files to and
  from gpg(1), checked versions 1.0.6, 1.4.1, 1.4.18, 2.1.18, 2.2.17.
* tool compatibility: command-line flags compatible with gpg(1), mostly
  with the same defaults.
* minimal dependencies: Works out-of-the-box with standard Python modules,
  but becomes much faster if PyCrypto is installed.
* any Python: works with any Python >=2.4, including Python 3.
* no regexps: the implementation doesn't use regexps, thus avoiding speed
  (and potential catastrophic speed) issues
* binary files: always opens files in binary mode, doesn't do any coversion on
  the plaintext (not even when decrypting, this is a difference from GPG)

Planned features:

* docs: Add full documentation for the file class API.

Explicit non-features:

* asymmetric (public key) encryption
* asymmetric (public key) signing
* gpg-agent support (e.g. storing passphrases in the agent)
* key management: ~/.gnupg/pubring.gpg and ~/.gnupg/secring.gpg
* asymmetric key (keypair) generation
* trust model

Dependencies:

* Python >=2.4. (Tested with: 2.4, 2.5, 2.6, 2.7, 3.0, 3.1, 3.2, 3.3, 3.4,
  3.5, 3.6, 3.7, 3.8.) If you use Debian or Ubuntu and you only
  have the minimal package installed (e.g.
  `sudo apt-get install python3.5-minimal', then all functionality except
  for bzip2 compression and decompression works).
* Optionally, PyCrypto for fast encryption and decryption. If PyCrypto is
  not available, embedded fallback pure Python code is used instead, but
  that can be >400 times slower than PyCrypto.
* Optionally, hashlib with OpenSSL for fast hashes (string-to-key and
  modification detection). If hashlib isn't available (or it doesn't
  support the hash needed), embedded fallback pure Python code is used
  instead, but that can be >400 times slower (~162 times for SHA-1)
  than hashlib with OpenSSL.
* Only for zip and zlib (de)compression, the standard Python module zip.
* Only for bzip2 (de)compression, the standard Python module bzip2.
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

Installation as a standalone command-line tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you have Python 2 (preferably with PyCrypto) installed, you can download
and use a the single-file, standalone command-line tool from
https://raw.githubusercontent.com/pts/tinygpgs/master/tinygpgs.single , make
it executable, and rename (or symlink) it to tinygpgs.

FYI to install Python 2 with PyCrypto on Debian-based Linux systems:

  $ sudo apt-get install python-pycrypto

Then on Linux you can download and use tinygpgs like this:

  $ wget -O tinygpgs.single https://raw.githubusercontent.com/pts/tinygpgs/master/tinygpgs.single 
  $ chmod +x tinygpgs.single
  $ ln -s tinygpgs.single tinygpgs
  $ ./tinygpgs

Alternatively, on macOS:

  $ curl -Lo tinygpgs.single https://raw.githubusercontent.com/pts/tinygpgs/master/tinygpgs.single
  $ chmod +x tinygpgs.single
  $ ln -s tinygpgs.single tinygpgs
  $ ./tinygpgs

You can install tinygpgs by copying the file (and the symlink) to somewhere
on your $PATH.

You can also use tinygpgs.single on Windows. After renaming it to tinygpgs,
run:

  $ python tinygpgs

See also ``Installation instructions and usage on Windows'' for all
installation steps (including Python installation) on Windows.

Installation as a Python module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you have Python 2 already installed, just run this command (maybe with
sudo to install for all users):

  $ python -m pip install tinygpgs pycrypto

To use the command-line tool, run it as `python -m tinygpgs.__main__'
instead of `./tinygpgs', except for Python 2.4, which requires
`python2.4 -m tinygpgs/__main'. For Python >=2.7, `python -m tinygpgs' also
works.

Installation instructions and usage on Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
There is no installer, you need to run some commands in the command line
(black Command Prompt window) to download and install. tinygpgs is a
command-line only application, there is no GUI.

Windows XP or newer (including Windows XP, Windows Vista, Windows 7, Windows
8, Windows 8.1 and Windows 10) is needed. 32-bit (i386, x86) or 64-bit
(amd64, x86_64, x64) versions are both fine (tinygpgs contains a 32-bit
Python 2.6 executable).

Create an empty directory and download these files there:

* https://github.com/pts/tinygpgs/releases/download/2019-12-10w/tinygpgs_win32exec.exe
* https://github.com/pts/tinygpgs/raw/master/tinygpgs.cmd
* https://github.com/pts/tinygpgs/raw/master/tinygpgs.single

In a Command Prompt window, cd into this direcrytory and run
tinygpgs_win32.exe. It will create some more files. Afterwards you can
remove it (del tinygpgs_win32exec.exe).

Now you can run tinygpgs as usual, e.g. `tinygpgs --help' (without the
quotes) from that directory. If you want to run it from any directory, then
add the directory containing tinygpgs.cmd to your PATH, or move all the
files to C:\Windows\System32.

To upgrade it, download a newer version of tinygpgs.single, and overwrite
that file.

Limitations:

* It's very slow, because it doesn't have and doesn't use PyCrypto.
* It doesn't work with filenames containing characters outside the CP-1252
  encoding (https://en.wikipedia.org/wiki/CP-1252), which is ASCII,
  ISO-8859-1, plus some Windows-specific characters. (This is a limitation
  of the Python 2.6 executable used).

Alteratively, if you already have Python installed (preferably with
PyCrypto, for the huge speed boost) on your Windows system, tinygpgs can use
that. The installation process is the same, but don't download or run
tinygpgs_win32exec.exe. (If you've run it already, delete
tinygpgs_python.exe, but better delete all the files and start downloading
again.) After that, tinygpgs.cmd will run tinygpgs.single with the
``python'' command on your system.

Using the file class API in the Python module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Install the Python module first, then see in
https://github.com/pts/tinygpgs/blob/master/tinygpgs.rst how to use the
file class API from your Python code.

Tools for decrypting symmetric key GPG message
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* gpg1: gpg -d <FILE.bin.gpg >FILE.bin
* gpg2: gpg -d --pinentry-mode loopback <FILE.bin.gpg >FILE.bin
* pgpy: python -c 'import getpass, sys, pgpy; sys.stdout.write(pgpy.PGPMessage.from_file(sys.argv[1]).decrypt(getpass.getpass("Enter passphrase: ")).message)' FILE.bin.gpg >FILE.bin
  installation: pip install pgpy  # Has lots of dependendes, use virtualenv.
* libgpgme (https://gnupg.org/software/gpgme/index.html): C library from the
  authors of GPG.

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

Unless otherwise indicated, benchmarks were run with Python 2.7.13 on a slow
Linux amd64 system running Debian 9.4.

Decryption (and decompression) benchmark measurements:

  gpg (GNUPG) 2.1.18.
  $ time gpg2 -d --pinentry-mode loopback <hellow5long.bin.gpg >hellow5long.out
  3.168s user

  With standard OpenSSL hashlib + PyCrypto.
  $ time python2.7 tinygpgs -d --passphrase abc <hellow5long.bin.gpg >hellow5long.out
  3.980s user

  With Python 3.5, standard OpenSSL hashlib + PyCrypto.
  $ time python3.5 tinygpgs -d --passphrase abc <hellow5long.bin.gpg >hellow5long.out
  4.388s user

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

Encryption (and compression) benchmark measurements:

  <FAST-ENCRYPTION> with standard OpenSSL hashlib + PyCrypto, default.
  $ time python2.7 tinygpgs -c --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  8.828s user

  <FAST-ENCRYPTION>, with Python 3.5.
  $ time python3.5 tinygpgs -c --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  8.940s user

  <FAST-ENCRYPTION>, without MDC, without compression. To be compared with encryptedfile.
  $ time python2.7 tinygpgs -c --cipher-algo aes-256 --passphrase abc --disable-mdc --compress-algo none <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256(9) is_py_cipher=0 s2k_mode=iterated-salted(3) s2k_digest_algo=sha1(2) is_py_digest=0 s2k_count=65536 len(s2k_salt)=8 compress_algo=uncompressed(0) compress_level=6 len(encrypted_session_key)=0 do_mdc=0 len(session_key)=32 bufcap=8192 literal_type='b' plain_filename='' mtime=0 do_add_ascii_armor=0
  0m2.336s user

  <FAST-ENCRYPTION>, with GpgSymmetricFileWriter file class API.
  $ time python2.7 tinygpgs -c --file-class --cipher-algo aes-256 --passphrase abc <hellow5long.bin >hellowc5long.bin.gpg
  info: GPG symmetric encrypt cipher_algo=aes-256 is_py_cipher=0 s2k_mode=iterated-salted digest_algo=sha1 is_py_digest=0 count=65536 len(salt)=8 len(encrypted_session_key)=0 do_mdc=1 len(session_key)=32
  7.984s user

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

  encryptedfile in text mode: This is very-very slow.
  $ time python -c 'import encryptedfile; f = encryptedfile.EncryptedFile("hellow5longef.bin.gpg", "abc", encryption_algo=encryptedfile.EncryptedFile.ALGO_AES256); f.write(open("hellow5long.gpg", "rb").read()); f.close()'
  1847.260s user

  encryptedfile in binary mode: This is very-very slow, possibly because of unnecessary string concatenations.
  $ time python -c 'import encryptedfile; f = encryptedfile.EncryptedFile("hellow5longef.bin.gpg", "abc", mode="wb", encryption_algo=encryptedfile.EncryptedFile.ALGO_AES256); f.write(open("hellow5long.gpg", "rb").read()); f.close()'
  1814.316s

  encryptedfile in binary mode, no compression.
  $ time python -c 'import encryptedfile; f = encryptedfile.EncryptedFile("hellow5longef.bin.gpg", "abc", mode="wb", encryption_algo=encryptedfile.EncryptedFile.ALGO_AES256); inf = open("../hellow5long.bin", "rb")
while 1:
  data = inf.read(8192)
  if not data: break
  f.write(data)
f.close()'
  0m4.200s user

__END__
