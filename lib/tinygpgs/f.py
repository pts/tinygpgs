"""Generic importer and source code fixer for Python 2.4 and 2.5.

Users shouldn't import it directly.
"""

import sys
import re
import os
import os.path
import sys


# The code in this file has no SyntaxError in Python >=2.4 (and Python 3)
# though.
if not (2, 4) <= sys.version_info[:2] < (2, 6):
  sys.exit(
      'fatal: Python version 2.4, 2.5 needed for: %s\n' % __file__)

if type(zip()) is not list:  # Python 3.
  exec('exec_func = exec')
else:
  exec('def exec_func(code, globals):\n  exec code in globals')


class MyImporter(object):
  """Importer which fixes Python source code for Python 2.4 and 2.5."""

  __slots__ = ()

  _FILE_CACHE = {}
  _PREFIX = '$LIB/'

  def __init__(self, name):
    if name != self._PREFIX[:-1] and not name.startswith(self._PREFIX):
      raise ImportError

  def find_module(self, name):
    namesl = name.replace('.', '/')
    filename = namesl + '.py'
    if filename not in self._FILE_CACHE:
      self._FILE_CACHE[filename] = self._file_exists(filename)
    if self._FILE_CACHE[filename]:
      return self
    filename = namesl + '/__init__.py'
    if filename not in self._FILE_CACHE:
      self._FILE_CACHE[filename] = self._file_exists(filename)
    if self._FILE_CACHE[filename]:
      return self
    return None

  def load_module(self, name):
    # TODO(pts): Does / work on Windows (Win32)?
    namesl = name.replace('.', '/')
    if self._FILE_CACHE[namesl + '.py']:
      filename = namesl + '.py'
      data = self._read_file_unl(filename)
      mod = type(sys)(name)  # Create new module.
    elif self._FILE_CACHE[namesl + '/__init__.py']:
      filename = namesl + '/__init__.py'
      data = self._read_file_unl(filename)
      mod = type(sys)(name)  # Create new module.
      mod.__path__ = [self._PREFIX + namesl]  # Must match.
    else:
      return None
    mod.__file__ = self._get_fake_filename(filename)  # Can be anything.
    sys.modules[name] = mod
    data = self._fix(data)
    code_obj = compile(data, mod.__file__, 'exec')
    exec_func(code_obj, mod.__dict__)  # Respects `coding:' etc.
    return mod

  @classmethod
  def _get_fake_filename(cls, filename):
    return LIBDIR + filename

  @classmethod
  def _file_exists(cls, filename):
    return os.path.isfile(LIBDIR + filename)

  @classmethod
  def _read_file_unl(cls, filename):
    f = open(LIBDIR + filename, 'U')
    try:
      return f.read()
    finally:
      f.close()

  _SPECIAL_RE = re.compile(r'[\'"#]|[ )]as (?=[a-zA-Z_]\w*:)')

  @classmethod
  def _fix(cls, data):
    """Convert Python 2.7 syntax to Python 2.4 syntax."""
    output = []
    i, j, ld, special_re = 0, 0, len(data), cls._SPECIAL_RE
    while 1:
      match = special_re.search(data, j)
      if not match:
        output.append(data[i:])
        break
      k = match.start()
      if data[k] == '#':
        j = (data.find('\n', j) + 1) or ld
        continue
      if data[k] in ') ':  # ' as '.
        output.append(data[i : k])
        if not data[k].isspace():
          output.append(data[k])
        output.append(', ')
        i = j = match.end()
        continue
      if k > 0 and data[k - 1] == 'b':
        output.append(data[i : k - 1])
        i = k  # Skip the 'b'.
      if k > 1 and data[k - 2] == 'br':
        output.append(data[i : k - 2])
        i = k - 1  # Skip the 'b'.
      d3 = data[k : k + 3]
      if d3 in ('"""', "'''"):
        qd = d3
      else:
        qd = data[k]
      j = k + 1
      while 1:  # Skip until end of string literal.
        j = data.find(qd, j)
        if j < 0:
          raise SyntaxError('Missing end of string literal.')
        k = j - 1
        while data[k] == '\\':
          k -= 1
        if (k - j) & 1:
          break
        j += 1
      j += len(qd)
    return ''.join(output)


class MyZipImporter(MyImporter):
  _FILE_CACHE = {}
  _PREFIX = '$ZIP/'

  def __init__(self, name):
    MyImporter.__init__(self, name)

  @classmethod
  def _get_fake_filename(cls, filename):
    return ''.join((ZIP_FILENAME, '/', filename))

  @classmethod
  def _file_exists(cls, filename):
    return filename in ZIP_NAMES

  @classmethod
  def _read_file_unl(cls, filename):
    return ZIP_FILE.read(filename).replace('\r\n', '\n').replace('\r', '\n')


if os.path.isdir(sys.path[0]):
  LIBDIR = os.path.join(sys.path[0], '')
  sys.path_hooks[:0] = [MyImporter]
  sys.path[0] = '$LIB'
  um = ''.join(__name__.split('.')[:-1])  # 'tinygpgs'.
  if um:
    sys.modules[um].__path__ = ['$LIB/' + um]  # Magic, import needs it.
elif os.path.isfile(sys.path[0]):
  import zipfile
  ZIP_FILENAME = sys.path[0]
  ZIP_FILE = zipfile.ZipFile(ZIP_FILENAME)
  ZIP_NAMES = ZIP_FILE.namelist()
  del zipfile  # Not in use anymore.
  sys.path_hooks[:] = [MyZipImporter]
  sys.path[0] = '$ZIP'
  um = ''.join(__name__.split('.')[:-1])  # 'tinygpgs'.
  if um:
    sys.modules[um].__path__ = ['$ZIP/' + um]  # Magic, import needs it.
else:
  sys.exit('fatal: Python library not found: %s' % sys.path[0])
