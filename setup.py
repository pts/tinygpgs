import sys

if sys.version_info[:2] < (2, 4):
  sys.exit('Sorry, Python <2.4 is not supported.')

import os
import os.path
import re
import sys
from distutils.core import setup


# A small variant of six.
if type(zip()) is not list:  # Python 3.
  def b(s):
    return bytes(s, 'ascii')
  def ascii(s):
    return str(s, 'ascii')
else:
  def b(s):
    return s
  def ascii(s):
    return s.encode('ascii').decode('ascii')

match = re.search(b(r'\nVERSION = \x27([^\x27\\\n]+)\x27\r?\n'),
                  open('lib/tinygpgs/main.py', 'rb').read())
assert match, 'missing version number'
version = ascii(match.group(1))

# --- SyntaxFixer for Python 2.4 and 2.5.
#
# Copy of some code in lib/tinygpgs/f.py.

class SyntaxFixer(object):
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


# --- Rest.


if sys.version_info[:2] < (2, 6) and 'sdist' not in sys.argv[1:]:
  assert os.path.isfile('lib/tinygpgs/main.py')
  # Fix the Python scripts: lib to libcompat.
  try:
    os.mkdir('libcompat')
  except OSError:
    pass
  try:
    os.mkdir('libcompat/tinygpgs')
  except OSError:
    pass
  oldcfns = set(entry for entry in os.listdir('libcompat/tinygpgs')
                if entry.endswith('.py'))
  for entry in os.listdir('lib/tinygpgs'):
    if not entry.endswith('.py'):
      continue
    infn = 'lib/tinygpgs/' + entry
    if os.path.isfile(infn):
      oldcfns.discard(entry)
      outfn = 'libcompat/tinygpgs/' + entry
      sys.stderr.write('info: fixing %s --> %s\n' % (infn, outfn))
      f = open(infn, 'rb')
      try:
        data = f.read()
      finally:
        f.close()
      data = SyntaxFixer._fix(data)
      f = open(outfn, 'wb')
      try:
        f.write(data)
      finally:
        f.close()
  for entry in oldcfns:
    outfn = 'libcompat/tinygpgs/' + entry
    try:
      os.remove(outfn)
    except OSError:
      pass
  libdir = 'libcompat'
else:
  libdir = 'lib'


try:
  os.remove('MANIFEST')  # Make sure it's not cached (lib vs libcompat).
except OSError:
  pass


setup(
    name='tinygpgs',
    version=version,
    author='pts',
    author_email='pts@fazekas.hu',
    packages=['tinygpgs'],
    package_dir={'': libdir},
    url='https://github.com/pts/tinygpgs',
    license='LICENSE.txt',
    description='symmetric key encryption and decryption compatible with GPG',
    long_description=ascii(open('tinygpgs.rst', 'rb').read()),
    # extras_require is a setuptools feature, it's a no-op here.
    extras_require={'fast': ['pycrypto (>= 2.6)']},
    # Optional, but strongly recommended for speed.
    #requires=['pycrypto (>= 2.6)'],
    requires=[],
)
