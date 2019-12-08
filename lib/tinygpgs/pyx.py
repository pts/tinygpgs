"""Python 2 and 3 compatibility layer, similar to six."""

if type(zip()) is not list:  # Python 3.
  binary_type, text_type = bytes, str
  integer_types = (int,)
  buffer_type = memoryview
  is_stdin_text = True
  xrange = range
  def ensure_binary(data):
    if isinstance(data, str):
      return bytes(data, 'utf-8')
    elif isinstance(data, bytes):
      return data
    else:
      raise TypeError
  def iteritems(d):
    return d.items()
  def buffer(a, _b=None, _c=None):
    if _b is None:
      return memoryview(a)
    elif _c is None:
      return memoryview(a)[_b:]
    else:
      return memoryview(a)[_b : _b + _c]
  try:
    bytes.hex  # Python >=3.5.
    def to_hex_str(data):  # Not in six.
      return data.hex()
  except AttributeError:
    def to_hex_str(data, _hexlify=__import__('binascii').hexlify):  # Not in six.
      return str(_hexlify(data), 'ascii')
  izip = zip  # Not in six.
  try:
    callable = callable
  except NameError:  # Python 3.1.
    def callable(obj):
      return bool(getattr(obj, '__call__', None))
else:  # Python 2.
  binary_type, text_type = str, unicode
  integer_types = (int, long)
  buffer = buffer_type = buffer
  is_stdin_text = False
  xrange = xrange
  def ensure_binary(data):
    if isinstance(data, unicode):
      return data.encode('utf-8')
    elif isinstance(data, str):
      return data
    else:
      raise TypeError
  def iteritems(d):
    return d.iteritems()
  def to_hex_str(data):  # Not in six.
    return data.encode('hex')
  from itertools import izip  # Not in six.
  callable = callable
# Python 3.x.
is_buffer_slice = type(buffer(b'')[:]) != type(b'')  # Not in six.
is_buffer_item_binary = type(buffer(b'x')[0]) == type(b'')
try:
  is_buffer_join = (b'y').join((buffer(b'x'),)) == b'x'  # Python >=3.4.
except (TypeError, ValueError):
  is_buffer_join = False
binary_types = (binary_type, buffer_type)
def check_binary(data):  # Not in six.
  if not isinstance(data, binary_type):
    raise TypeError
  return data
