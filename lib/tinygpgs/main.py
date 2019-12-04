"""Encryption and decryption command-line tool with gpg(1) compatibility."""

import sys

# Here we don't import anything from tinygpgs, to make --help and flag
# parsing fast. We do lazy imports later as needed.

# !! gpg -d: WARNING: message was not integrity protected
# !! Add tests for ciphers and hashes.
# !! Add Python 3 support.
# !! Add warning if slow becaue of Python hash or cipher.
# !! Document encryptedfile and other Python modules.

# This line is read by setup.py.
VERSION = '0.11'

# --- Passphrase prompt.


def prompt_passphrase(do_passphrase_twice):
  sys.stderr.flush()
  sys.stdout.flush()
  import getpass
  # Unfortunately in Python 2.4 and 2.5, this raises a termios.error if
  # stdin is redirected to a file. As a workaround, upgrade to Python >=2.6,
  # or use `--passphrase ...'.
  passphrase = getpass.getpass('Enter passphrase: ')
  if not passphrase:
    raise SystemExit('fatal: empty passphrase')
  if do_passphrase_twice:
    passphrase2 = getpass.getpass('Re-enter passphrase: ')
    if passphrase != passphrase2:
      raise SystemExit('fatal: passphrases do not match')
  return passphrase


# --- Platform-specific code.


def set_fd_binary(fd):
  """Make sure that os.write(fd, ...) doesn't write extra \r bytes etc."""
  import sys
  if sys.platform.startswith('win'):
    import os
    import msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)


# --- Command-line parsing and main().

FLAG_DOC = r"""
Encryption and decryption flags:

* --pinentry-mode <value>: Value must be loopback. Otherwise ignored for PGP
  2.x compatibility.
* --slow-cipher: Use the slow, pure Python implementation of the ciphers.
* --no-slow-cipher: Use the fast, C extension implementation (PyCrypto) of the
  ciphers, if available. Otherwise, use the slow, pure Python implementation.
* --slow-hash: Use the slow, pure Python implementation of the hashes.
* --no-slow-hash: Use the fast, C extension implementation (PyCrypto) of the
  hashes, if available. Otherwise, use the slow, pure Python implementation.
* --file-class: Use the GpgSymmetricFile* class API to do the work. It's a bit
  slower than the function-based API, so it's not recommended for regular use.
* --no-file-class: Use the function API to do the work.
* --batch: Don't ask the user. Fail if no passphrase given on the command line.
* --no-batch: Ask the user if needed. Typically the passphrase is asked.
* --yes: Auto-answer yes to questions. Will overwrite existing output files.
* --no: Don't answer yes to questions. Will abort if the output file already
  exists, and will keep it intact.
* --quiet (-q, --no-show-info): Don't show file parameters on stderr.
* --verbose (-v, --show-info): Show file parameters on stderr.
* --show-session-key: Show the session key (block cipher key) on stderr.
  Insecure, should be used for debugging or during coercion only.
* --no-show-session-key: Don't show the session key on stderr. Default.
* --passphrase <pass>: Use the specified passphrase. This
  flag is insecure (because it adds the passphrase to your shell history),
  please don't specify it, but type the passphrases interactively or use
  --passphrase-file ... or --passphrase-fd ... instead.
* --passphrase-file <file>: Read the first line of <file> and use it (without
  the trailing line breaks) as passphrase.
* --passphrase-fd <fd>: Read the first line from file descriptor <fd> (e.g. 0
  for stdin), and use it (without the trailing line breaks) as passphrase.
  Be careful: if stdin is used and it's a TTY, it will echo the passphrase.
* --passphrase-repeat <n>: If <n> is more than 1, ask the passphrase twice
  before encryption. Doesn't affect decryption.
* --bufcap <n>: Use buffer size of (approximately) <n> throughout, and also use
  it as GP partial packet size. <n> must be a power of 2 at least 512. The
  default is 8192.
* --output (-o) <file>: Write the output to <file> instead of stdout.

Encryption-only flags:

* --cipher-algo <algo>: Use the specified encryption algorithm. Values:
  idea, 3des (des3), cast5, blowfish, aes-128, aes-192, aes-256,
  twofish-256, des, twofish-128.
* --digest-algo <algo>: Use the specified hash for string-to-key. Values:
  md5, sha1, ripemd160, sha256, sha384, sha512, sha224.
* --compress-algo <algo>: Use the specified compression algorithm. Values:
  none (uncompressed), zlib, zlib, bzip2.
* --compress-level <n>: 0: disable compression, 1: fastest, low effort
  compression, ..., 6: default compression effort, ..., 9: slowest compression.
* --bzip2-compress-level <n>: Like --compress-level ..., but applies only if
  --compress-algo bzip2 is active.
( -a (--armor): Wrap output in ASCII armor (header and Base64 encoding).
* --no-armor: Don't wrap output in ASCII armor.
* --s2k-mode <n>. Use the specified string-to-key mode. Values:
  0: simple, 1: 1: salted, 3: iterated-salted.
* --s2k-count <n>: Run the hash over approximately <n> bytes for --s2k-mode 3.
* --force-mdc: Enable appending of modification-detection code (MDC, hash,
  message digest). Default.
* --disable-mdc: Omit the modification-detection code from the output.
* --plain-filename <file>: Store the specified filename in the output.
* --literal-type <c>: Store the specified file type in the output. The value
  b indicates binary, other values are not recommended. No matter this flag
  value, all files are treated as binary.
* --mtime <mtime>: Store the specified last modification time in the output.
  The value is an integer, the Unix timestamp. The default is 0.
"""

def usage(argv0, do_flags=False):
  flag_doc = FLAG_DOC * bool(do_flags)
  if flag_doc.startswith('\n '):
    flag_doc = flag_doc.replace('\n ', '\n')
  sys.stderr.write(
      'tinygpgs v%s: symmetric key encryption tool compatible with GPG\n'
      'This is free software, MIT license. '
      'There is NO WARRANTY. Use at your risk.\n'
      'encryption usage: %s -c [<flag> ...] [FILE.bin]\n'
      'decryption usage: %s -d [<flag> ...] FILE.bin.gpg >FILE.bin\n'
      'https://github.com/pts/tinygpgs\n%s' %
      (VERSION, argv0, argv0, flag_doc))


def get_flag_arg(argv, i):
  if i >= len(argv):
    raise SystemExit('usage: missing argument for flag: ' + argv[i - 1])
  return argv[i]


def get_flag_arg_int(argv, i):
  value = get_flag_arg(argv, i)
  try:
    return int(value)
  except ValueError:
    # TODO(pts): Check for positive value etc.
    raise SystemExit('usage: flag value must be an integer: %s %s' % (argv[i - 1], argv[i]))


def read_passphrase_from_fd(fd):
  # We need binary mode for 8-bit accurate s2k.
  set_fd_binary(fd)
  import os
  # Don't read more bytes than needed.
  output = []
  while 1:
    c = os.read(fd, 1)  # Don't read too much.
    if not c or c in '\r\n':
      # No need for os.close(fd).
      return ''.join(output)
    output.append(c)


def show_info(msg):
  sys.stderr.write('info: %s\n' % (msg,))
  sys.stderr.flush()  # Automatic, but play it safe.


def main(argv, zip_file=None):
  if len(argv) < 2:
    usage(argv[0])
    sys.exit(1)
  argv = list(argv)
  is_file_class = is_batch = do_passphrase_twice = is_yes_flag = False
  output_file = input_file = None
  bufcap = 8192
  params = {}
  params['passphrase'] = ()
  params['show_info_func'] = show_info
  encrypt_params = {}
  if argv[1] in ('-c', '--symmetric'):  # Like gpg(1).
    do_encrypt = True
  elif argv[1] in ('-d', '--decrypt'):  # Like gpg(1).
    do_encrypt = False
  elif argv[1] in ('-e', '--encrypt', '-s', '--sign', '--verify'):  # Like gpg(1).
    raise SystemExit('usage: public-key cryptography not supported: %s' % argv[1])
  elif argv[1] == '--help':
    return usage(argv[0], True)
  else:
    usage(argv[0])
    sys.exit(1)
  i = 2
  while i < len(argv):
    arg = argv[i]
    if arg == '-' or not arg.startswith('-'):
      break
    i += 1
    is_yes = not arg.startswith('--no-')
    if arg == '--':
      break
    elif arg == '--pinentry-mode':  # gpg(1).
      if get_flag_arg(argv, i) != 'loopback':
        raise SystemExit('usage: invalid flag value for --pinentry-mode: ' + argv[i])
      i += 1
    elif arg in ('--slow-cipher', '--no-slow-cipher'):
      params['is_slow_cipher'] = is_yes
    elif arg == ('--slow-hash', '--no-slow-hash'):
      params['is_slow_hash'] = is_yes
    elif arg in ('--file-class', '--no-file-class'):
      is_file_class = is_yes
    elif arg in ('--batch', '--no-batch'):  # gpg(1).
      is_batch = is_yes
    elif arg == '--yes':  # gpg(1).
      is_yes_flag = True
    elif arg == '--no':  # gpg(1).
      is_yes_flag = False
    elif arg in ('-q', '--quiet'):  # gpg(1).
      params['show_info_func'] = False
    elif arg in ('-v', '--verbose'):  # gpg(1).
      params['show_info_func'] = show_info
    elif arg in ('--show-info', '--no-show-info'):
      params['show_info_func'] = is_yes and show_info
    elif arg in ('--show-session-key', '--no-show-session-key'):  # gpg(1).
      params['do_show_session_key'] = is_yes
    elif arg == '--passphrase':  # gpg(1).
      params['passphrase'] = get_flag_arg(argv, i)
      i += 1
    elif arg == '--passphrase-fd':  # gpg(1).
      params['passphrase'] = get_flag_arg_int(argv, i)
      i += 1
    elif arg == '--passphrase-file':  # gpg(1).
      params['passphrase'] = [get_flag_arg(argv, i)]
      i += 1
    elif arg == '--passphrase-repeat':  # gpg(1).
      # GPG 2.1.18 ignores this flag with `--pinentry-mode loopback'. We use
      # it for a repeated passphrase prompt.
      do_passphrase_twice = get_flag_arg_int(argv, i) > 1
      i += 1
    elif arg == '--bufcap':
      bufcap = get_flag_arg_int(argv, i)
      i += 1
    elif arg in ('-o', '--output'):  # gpg(1).
      output_file = get_flag_arg(argv, i)
      i += 1
    elif do_encrypt and arg == '--cipher-algo':  # gpg(1).
      encrypt_params['cipher'] = get_flag_arg(argv, i)
      i += 1
    elif do_encrypt and arg in ('--digest-algo', '--s2k-digest-algo'):  # gpg(1).
      encrypt_params['s2k_digest'] = get_flag_arg(argv, i)
      i += 1
    elif do_encrypt and arg == '--compress-algo':  # gpg(10>
      encrypt_params['compress'] = get_flag_arg(argv, i)
      i += 1
    elif do_encrypt and arg in ('-a', '--armor', '--no-armor'):  # gpg(1).
      encrypt_params['do_add_ascii_armor'] = is_yes
    elif do_encrypt and arg in ('-z', '--compress-level'):  # gpg(1).
      encrypt_params['compress_level'] = get_flag_arg_int(argv, i)
      i += 1
    elif do_encrypt and arg == '--bzip2-compress-level':  # gpg(1).
      encrypt_params['bzip2_compress_level'] = get_flag_arg_int(argv, i)
      i += 1
    elif do_encrypt and arg == '--s2k-mode':  # gpg(1).
      encrypt_params['s2k_mode'] = get_flag_arg_int(argv, i)
      i += 1
    elif do_encrypt and arg == '--s2k-count':  # gpg(1).
      encrypt_params['s2k_count'] = get_flag_arg_int(argv, i)
      i += 1
    elif do_encrypt and arg == '--force-mdc':  # gpg(1).
      encrypt_params['do_mdc'] = True
    elif do_encrypt and arg == '--disable-mdc':  # gpg(1).
      encrypt_params['do_mdc'] = False
    elif do_encrypt and arg == '--plain-filename':
      encrypt_params['plain_filename'] = get_flag_arg(argv, i)
      i += 1
    elif do_encrypt and arg == '--literal-type':
      encrypt_params['literal_type'] = get_flag_arg(argv, i)
      i += 1
    elif do_encrypt and arg == '--mtime':
      encrypt_params['mtime'] = get_flag_arg_int(argv, i)
      i += 1
    else:
      raise SystemExit('usage: unknown flag: ' + arg)
  if i < len(argv) and input_file is None:  # gpg(1).
    input_file = argv[i]
    i += 1
  if i != len(argv):
    raise SystemExit('usage: too many command-line arguments')
  if input_file is None:
    input_file = '-'
  if output_file is None:
    if do_encrypt and input_file != '-':
      output_file = input_file + '.gpg'  # gpg(1).
    else:
      output_file = '-'
  if bufcap < 1 or bufcap & (bufcap - 1):
    raise SystemExit('usage: --bufcap value must be a power of 2, got: %d' % bufcap)
  buflog2cap = 1
  while bufcap > (1 << buflog2cap):
    buflog2cap += 1
  assert bufcap == 1 << buflog2cap  # Just to make sure.
  if buflog2cap > 30:
    raise SystemExit('usage: --bufcap value too large, must be at most %d, got: %d' % (1 << 30, bufcap))
  if buflog2cap < 9:
    # Some ciphers need >= 16, GPG partial packets need at least 512.
    raise SystemExit('usage: --bufcap value too small, must be at least %d, got: %d' % (1 << 9, bufcap))
  if isinstance(params['passphrase'], list):  # File:
    # We need binary mode for 8-bit accurate s2k.
    try:
      f = open(params['passphrase'][0], 'rb')
    except IOError, e:
      raise SystemExit('fatal: error opening the passphrase file: %s' % e)
    try:
      params['passphrase'] = f.readline().rstrip('\r\n')
    finally:
      f.close()
  elif isinstance(params['passphrase'], (int, long)):  # File descroptor.
    params['passphrase'] = read_passphrase_from_fd(params['passphrase'])
  elif params['passphrase'] is ():  # Interactive prompt.
    if is_batch:
      raise SystemExit('usage: passphrase prompt conflicts with --batch mode')
    params['passphrase'] = lambda is_twice=do_encrypt and do_passphrase_twice: (
        prompt_passphrase(is_twice))

  inf, of = sys.stdin, sys.stdout
  try:
    if input_file == '-':
      set_fd_binary(inf.fileno())
    else:
      inf = open(input_file, 'rb')
    if output_file == '-':
      set_fd_binary(of.fileno())
    else:
      if not is_yes_flag:
        import os.path
        # TODO(pts): Like gpg(1), don't clobber the output on a decrypt
        # attempt with a bad passphrase or on a user abort during the
        # passphrase prompt.
        if os.path.exists(output_file):
          # gpg(1) asks the user interactively after the passphrase prompt.
          raise SystemExit('fatal: output file exists, not overwriting: %s' %
                           output_file)
      of = open(output_file, 'wb')
    if do_encrypt:
      encrypt_params.update(params)  # Shouldn't have common fields.
      encrypt_params['buflog2cap'] = buflog2cap
      if ('bzip2_compress_level' in encrypt_params and
          encrypt_params.get('compress', '').lower() == 'bzip2'):
        encrypt_params['compress_level'] = encrypt_params.pop('bzip2_compress_level')
      # Defaults in GPG <2.1, including 1.4.18.
      #encrypt_params.setdefault('cipher', 'sha256')
      #encrypt_params.setdefault('compress', 'none')
      #encrypt_params.setdefault('compress_level', 9)
      #encrypt_params.setdefault('do_mdc', False)
      from tinygpgs import gpgs
      if is_file_class:
        from tinygpgs import file  # Lazy import to make startup (flag parsing) fast.
        f = file.GpgSymmetricFileWriter(of.write, 'wb', **encrypt_params)
        try:
          while 1:
            data = inf.read(bufcap)
            if not data:
              break
            f.write(data)
        finally:
          f.close()
      else:
        gpgs.encrypt_symmetric_gpg(inf.read, of, **encrypt_params)
    else:
      from tinygpgs import gpgs
      try:
        if is_file_class:
          from tinygpgs import file
          f = file.GpgSymmetricFileReader(inf.read, 'rb', **params)
          try:
            #of.write(f.read()); return  # Works but uses much memory.
            while 1:
              data = f.read(bufcap)
              if not data:
                break
              of.write(data)
          finally:
            f.close()
        else:
          gpgs.decrypt_symmetric_gpg(inf.read, of, **params)
      except gpgs.BadPassphraseError, e:
        msg = str(e)
        sys.stderr.write('fatal: %s%s\n' % (msg[0].lower(), msg[1:].rstrip('.')))
        sys.exit(2)
  finally:
    try:
      if of is not sys.stdout:
        of.close()
    finally:
      if inf is not sys.stdin:
        inf.close()
