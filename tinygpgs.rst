========
tinygpgs
========
tinygpgs is a fast module and standalone Python 2 script for doing
symmetric key (passphrase-based) encryption and decryption using the OpenPGP
file format compatible with GPG (GnuPG).

-----
Usage
-----
File class API usage for encryption::

    import getpass
    from tinygpgs.file import GpgSymmetricFile
    f = GpgSymmetricFile('FILE.bin.gpg', 'wb', getpass.getpass())
    try:
      f.write('Hello, World!\n')
      f.write('This is the end.\n')
    finally:
      f.close()

File class API usage for decryption::

    import getpass 
    from tinygpgs.file import GpgSymmetricFile
    f = GpgSymmetricFile('FILE.bin', 'rb', getpass.getpass())
    try:
      # Use f.read(8192) in a loop instead to limit memory usage.
      print(f.read())
    finally:
      f.close()

For encryption, it also provides the `encryptedfile
<https://pypi.org/project/encryptedfile/>`_ 1.1.1 interface for easy
migration::

    import getpass
    from tinygpgs.file import EncryptedFile  # Just for compatibility.
    f = EncryptedFile('FILE.bin.gpg', mode='wb', passphrase=getpass.getpass())
    try:
      f.write('Hello, World!\n')
      f.write('This is the end.\n')
    finally:
      f.close()

Command-line tool usage::

    $ python -m tinygpgs -c FILE.bin                  # Encrypt.
    Enter passphrase:
    $ python -m tinygpgs -d <FILE.bin.gpg >FILE2.bin  # Decrypt.
    Enter passphrase:
    $ cmp FILE.bin FILE2.bin

The command-line tool has many flags identical to gpg(1), so you can use
``python -m tinygpgs`` as a drop-in replacement for ``gpg`` for symmetric
key encryption and decryption.

--------
Features
--------
tinygpgs supports all ciphers, hashes, string-to-key modes, output formats
(binary and ASCII armor) and compression methods in the `OpenPGP RFC
<https://tools.ietf.org/html/rfc4880>`_ for both encryption and decryption.
All these settings are configurable in keyword arguments to the class
constructors and in command-line flags.

tinygpgs doesn't support public-key cryptography (e.g. encryption, signing
and key generation).

------------
Installation
------------
To get the module, run this::

    $ python -m pip install tinygpgs pycrypto

Please note that tinygpgs works without *pycrypto* as well, but with
*pycrypto* it works much faster, even comparable with gpg(1): less than 1.37
slower.

To get the standalone version of the command-line tool (single executable
file for Unix, contains the module embedded), see
https://github.com/pts/tinygpgs.

You need Python >=2.4 to use tinygpgs as a script or a module. It was tested
with 2.4 and 3.8, and all the major versions in-between.

---------
More info
---------
See see https://github.com/pts/tinygpgs.

-------
License
-------
tinygpgs is free software released under the MIT license. There is NO
WARRANTY. Use at your risk.
