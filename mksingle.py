#! /usr/bin/python
# by pts@fazekas.hu at Fri Sep  1 16:34:46 CEST 2017

"""Build single-file script for Unix: tinygpgs.single.

This script needs Python >=2.4, it also works with Python 3. In earlier
Python versions it raises SyntaxError.
"""

import os
import os.path
import re
import subprocess
import sys
import time
import zipfile

# A small variant of six.
if type(zip()) is not list:  # Python 3.
  binary_type = bytes
  def b(s):
    return bytes(s, 'ascii')
  try:
    callable
  except NameError:  # Python 3.1.
    def callable(obj):
      return bool(getattr(obj, '__call__', None))
else:
  binary_type = str
  def b(s):
    return s

# --- Tokenizer.

"""Tokenization help for Python programs.

Based on Lib/tonkenize.py in Python 2.7.13, wit syntax converted back to
Python 2.4, and untokenize removed.

generate_tokens(readline) is a generator that breaks a stream of
text into Python tokens.  It accepts a readline-like method which is called
repeatedly to get the next line of input (or "" for EOF).  It generates
5-tuples with these members:

    the token type (see token.py)
    the token (a string)
    the starting (row, column) indices of the token (a 2-tuple of ints)
    the ending (row, column) indices of the token (a 2-tuple of ints)
    the original line (string)

It is designed to match the working of the Python tokenizer exactly, except
that it produces COMMENT tokens for comments and gives type OP for all
operators
"""

#__author__ = 'Ka-Ping Yee <ping@lfw.org>'
#__credits__ = ('GvR, ESR, Tim Peters, Thomas Wouters, Fred Drake, '
#               'Skip Montanaro, Raymond Hettinger')

from itertools import chain
import string, re

tok_name = {}
def add_token_constants(**kwargs):
  g = globals()
  for k, v in kwargs.items():
    tok_name[v], g[k] = k, v

add_token_constants(
    ENDMARKER=0, NAME=1, NUMBER=2, STRING=3, NEWLINE=4, INDENT=5, DEDENT=6,
    LPAR=7, RPAR=8, LSQB=9, RSQB=10, COLON=11, COMMA=12, SEMI=13, PLUS=14,
    MINUS=15, STAR=16, SLASH=17, VBAR=18, AMPER=19, LESS=20, GREATER=21,
    EQUAL=22, DOT=23, PERCENT=24, BACKQUOTE=25, LBRACE=26, RBRACE=27,
    EQEQUAL=28, NOTEQUAL=29, LESSEQUAL=30, GREATEREQUAL=31, TILDE=32,
    CIRCUMFLEX=33, LEFTSHIFT=34, RIGHTSHIFT=35, DOUBLESTAR=36, PLUSEQUAL=37,
    MINEQUAL=38, STAREQUAL=39, SLASHEQUAL=40, PERCENTEQUAL=41,
    AMPEREQUAL=42, VBAREQUAL=43, CIRCUMFLEXEQUAL=44, LEFTSHIFTEQUAL=45,
    RIGHTSHIFTEQUAL=46, DOUBLESTAREQUAL=47, DOUBLESLASH=48,
    DOUBLESLASHEQUAL=49, AT=50, OP=51, ERRORTOKEN=52,
    COMMENT=53, NL=54,  # tokenize.py.
    N_TOKENS=55, NT_OFFSET=256)

def ISTERMINAL(x):
    return x < NT_OFFSET

def ISNONTERMINAL(x):
    return x >= NT_OFFSET

def ISEOF(x):
    return x == ENDMARKER

def group(*choices): return '(' + '|'.join(choices) + ')'
def any(*choices): return group(*choices) + '*'
def maybe(*choices): return group(*choices) + '?'

Whitespace = r'[ \f\t]*'
Comment = r'#[^\r\n]*'
Ignore = Whitespace + any(r'\\\r?\n' + Whitespace) + maybe(Comment)
Name = r'[a-zA-Z_]\w*'

Hexnumber = r'0[xX][\da-fA-F]+[lL]?'
Octnumber = r'(0[oO][0-7]+)|(0[0-7]*)[lL]?'
Binnumber = r'0[bB][01]+[lL]?'
Decnumber = r'[1-9]\d*[lL]?'
Intnumber = group(Hexnumber, Binnumber, Octnumber, Decnumber)
Exponent = r'[eE][-+]?\d+'
Pointfloat = group(r'\d+\.\d*', r'\.\d+') + maybe(Exponent)
Expfloat = r'\d+' + Exponent
Floatnumber = group(Pointfloat, Expfloat)
Imagnumber = group(r'\d+[jJ]', Floatnumber + r'[jJ]')
Number = group(Imagnumber, Floatnumber, Intnumber)

# Tail end of ' string.
Single = r"[^'\\]*(?:\\.[^'\\]*)*'"
# Tail end of " string.
Double = r'[^"\\]*(?:\\.[^"\\]*)*"'
# Tail end of ''' string.
Single3 = r"[^'\\]*(?:(?:\\.|'(?!''))[^'\\]*)*'''"
# Tail end of """ string.
Double3 = r'[^"\\]*(?:(?:\\.|"(?!""))[^"\\]*)*"""'
Triple = group("[uUbB]?[rR]?'''", '[uUbB]?[rR]?"""')
# Single-line ' or " string.
String = group(r"[uUbB]?[rR]?'[^\n'\\]*(?:\\.[^\n'\\]*)*'",
               r'[uUbB]?[rR]?"[^\n"\\]*(?:\\.[^\n"\\]*)*"')

# Because of leftmost-then-longest match semantics, be sure to put the
# longest operators first (e.g., if = came before ==, == would get
# recognized as two instances of =).
Operator = group(r"\*\*=?", r">>=?", r"<<=?", r"<>", r"!=",
                 r"//=?",
                 r"[+\-*/%&|^=<>]=?",
                 r"~")

Bracket = '[][(){}]'
Special = group(r'\r?\n', r'[:;.,`@]')
Funny = group(Operator, Bracket, Special)

PlainToken = group(Number, Funny, String, Name)
Token = Ignore + PlainToken

# First (or only) line of ' or " string.
ContStr = group(r"[uUbB]?[rR]?'[^\n'\\]*(?:\\.[^\n'\\]*)*" +
                group("'", r'\\\r?\n'),
                r'[uUbB]?[rR]?"[^\n"\\]*(?:\\.[^\n"\\]*)*' +
                group('"', r'\\\r?\n'))
PseudoExtras = group(r'\\\r?\n|\Z', Comment, Triple)
PseudoToken = Whitespace + group(PseudoExtras, Number, Funny, ContStr, Name)

tokenprog, pseudoprog, single3prog, double3prog = map(
    re.compile, (Token, PseudoToken, Single3, Double3))
endprogs = {"'": re.compile(Single), '"': re.compile(Double),
            "'''": single3prog, '"""': double3prog,
            "r'''": single3prog, 'r"""': double3prog,
            "u'''": single3prog, 'u"""': double3prog,
            "ur'''": single3prog, 'ur"""': double3prog,
            "R'''": single3prog, 'R"""': double3prog,
            "U'''": single3prog, 'U"""': double3prog,
            "uR'''": single3prog, 'uR"""': double3prog,
            "Ur'''": single3prog, 'Ur"""': double3prog,
            "UR'''": single3prog, 'UR"""': double3prog,
            "b'''": single3prog, 'b"""': double3prog,
            "br'''": single3prog, 'br"""': double3prog,
            "B'''": single3prog, 'B"""': double3prog,
            "bR'''": single3prog, 'bR"""': double3prog,
            "Br'''": single3prog, 'Br"""': double3prog,
            "BR'''": single3prog, 'BR"""': double3prog,
            'r': None, 'R': None, 'u': None, 'U': None,
            'b': None, 'B': None}

triple_quoted = {}
for t in ("'''", '"""',
          "r'''", 'r"""', "R'''", 'R"""',
          "u'''", 'u"""', "U'''", 'U"""',
          "ur'''", 'ur"""', "Ur'''", 'Ur"""',
          "uR'''", 'uR"""', "UR'''", 'UR"""',
          "b'''", 'b"""', "B'''", 'B"""',
          "br'''", 'br"""', "Br'''", 'Br"""',
          "bR'''", 'bR"""', "BR'''", 'BR"""'):
    triple_quoted[t] = t
single_quoted = {}
for t in ("'", '"',
          "r'", 'r"', "R'", 'R"',
          "u'", 'u"', "U'", 'U"',
          "ur'", 'ur"', "Ur'", 'Ur"',
          "uR'", 'uR"', "UR'", 'UR"',
          "b'", 'b"', "B'", 'B"',
          "br'", 'br"', "Br'", 'Br"',
          "bR'", 'bR"', "BR'", 'BR"' ):
    single_quoted[t] = t

tabsize = 8

class TokenError(Exception): pass

class StopTokenizing(Exception): pass

def generate_tokens(readline):
    """
    The generate_tokens() generator requires one argument, readline, which
    must be a callable object which provides the same interface as the
    readline() method of built-in file objects. Each call to the function
    should return one line of input as a string.  Alternately, readline
    can be a callable function terminating with StopIteration:
        readline = open(myfile).next    # Example of alternate readline

    The generator produces 5-tuples with these members: the token type; the
    token string; a 2-tuple (srow, scol) of ints specifying the row and
    column where the token begins in the source; a 2-tuple (erow, ecol) of
    ints specifying the row and column where the token ends in the source;
    and the line on which the token was found. The line passed is the
    logical line; continuation lines are included.
    """
    lnum = parenlev = continued = 0
    namechars, numchars = string.ascii_letters + '_', '0123456789'
    contstr, needcont = '', 0
    contline = None
    indents = [0]

    while 1:                                   # loop over lines in stream
        try:
            line = readline()
        except StopIteration:
            line = ''
        lnum += 1
        pos, max = 0, len(line)

        if contstr:                            # continued string
            if not line:
                raise TokenError("EOF in multi-line string", strstart)
            endmatch = endprog.match(line)
            if endmatch:
                pos = end = endmatch.end(0)
                yield (STRING, contstr + line[:end],
                       strstart, (lnum, end), contline + line)
                contstr, needcont = '', 0
                contline = None
            elif needcont and line[-2:] != '\\\n' and line[-3:] != '\\\r\n':
                yield (ERRORTOKEN, contstr + line,
                           strstart, (lnum, len(line)), contline)
                contstr = ''
                contline = None
                continue
            else:
                contstr = contstr + line
                contline = contline + line
                continue

        elif parenlev == 0 and not continued:  # new statement
            if not line: break
            column = 0
            while pos < max:                   # measure leading whitespace
                if line[pos] == ' ':
                    column += 1
                elif line[pos] == '\t':
                    column = (column//tabsize + 1)*tabsize
                elif line[pos] == '\f':
                    column = 0
                else:
                    break
                pos += 1
            if pos == max:
                break

            if line[pos] in '#\r\n':           # skip comments or blank lines
                if line[pos] == '#':
                    comment_token = line[pos:].rstrip('\r\n')
                    nl_pos = pos + len(comment_token)
                    yield (COMMENT, comment_token,
                           (lnum, pos), (lnum, pos + len(comment_token)), line)
                    yield (NL, line[nl_pos:],
                           (lnum, nl_pos), (lnum, len(line)), line)
                else:
                    yield ((NL, COMMENT)[line[pos] == '#'], line[pos:],
                           (lnum, pos), (lnum, len(line)), line)
                continue

            if column > indents[-1]:           # count indents or dedents
                indents.append(column)
                yield (INDENT, line[:pos], (lnum, 0), (lnum, pos), line)
            while column < indents[-1]:
                if column not in indents:
                    raise IndentationError(
                        "unindent does not match any outer indentation level",
                        ("<tokenize>", lnum, pos, line))
                indents = indents[:-1]
                yield (DEDENT, '', (lnum, pos), (lnum, pos), line)

        else:                                  # continued statement
            if not line:
                raise TokenError("EOF in multi-line statement", (lnum, 0))
            continued = 0

        while pos < max:
            pseudomatch = pseudoprog.match(line, pos)
            if pseudomatch:                                # scan for tokens
                start, end = pseudomatch.span(1)
                spos, epos, pos = (lnum, start), (lnum, end), end
                if start == end:
                    continue
                token, initial = line[start:end], line[start]

                if initial in numchars or \
                   (initial == '.' and token != '.'):      # ordinary number
                    yield (NUMBER, token, spos, epos, line)
                elif initial in '\r\n':
                    if parenlev > 0:
                        yield (NL, token, spos, epos, line)
                    else:
                        yield (NEWLINE, token, spos, epos, line)
                elif initial == '#':
                    assert not token.endswith("\n")
                    yield (COMMENT, token, spos, epos, line)
                elif token in triple_quoted:
                    endprog = endprogs[token]
                    endmatch = endprog.match(line, pos)
                    if endmatch:                           # all on one line
                        pos = endmatch.end(0)
                        token = line[start:pos]
                        yield (STRING, token, spos, (lnum, pos), line)
                    else:
                        strstart = (lnum, start)           # multiple lines
                        contstr = line[start:]
                        contline = line
                        break
                elif initial in single_quoted or \
                    token[:2] in single_quoted or \
                    token[:3] in single_quoted:
                    if token[-1] == '\n':                  # continued string
                        strstart = (lnum, start)
                        endprog = (endprogs[initial] or endprogs[token[1]] or
                                   endprogs[token[2]])
                        contstr, needcont = line[start:], 1
                        contline = line
                        break
                    else:                                  # ordinary string
                        yield (STRING, token, spos, epos, line)
                elif initial in namechars:                 # ordinary name
                    yield (NAME, token, spos, epos, line)
                elif initial == '\\':                      # continued stmt
                    continued = 1
                else:
                    if initial in '([{':
                        parenlev += 1
                    elif initial in ')]}':
                        parenlev -= 1
                    yield (OP, token, spos, epos, line)
            else:
                yield (ERRORTOKEN, line[pos],
                           (lnum, pos), (lnum, pos+1), line)
                pos += 1

    for indent in indents[1:]:                 # pop remaining indent levels
        yield (DEDENT, '', (lnum, 0), (lnum, 0), '')
    yield (ENDMARKER, '', (lnum, 0), (lnum, 0), '')


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

_NONASCII_RE = re.compile(r'[^\x00-\x7e]')


def minify_str(source, output_func):
  """Minifies (a subset of) Python 2.4 ... 3.8 source code.

  This function was tested and it works identically (consistently) in Python
  2.4, 2.5, 2.6 and 2.7.

  The output will end with a newline, unless empty.

  This function does this:

  * Removes comments.
  * Compresses indentation to 1 space at a time.
  * Removes empty lines and consecutive duplicate newlines.
  * Removes newlines within expressions.
  * Removes unnecessary whitespace within a line (e.g. '1 + 2' to '1+2').
  * Removes strings at the beginning of the expression (including docstring).
  * Removes even the first comment line with '-*- coding '... .

  This function doesn't do these:

  * Removing the final newline ('\\n').
  * Shortening the names of local variables.
  * Making string literals shorter by better escaping etc.
  * Compressing compound statements to 1 line, e.g.
    'if x:\\ny=5\\n' to 'if x:y=5\\n'.
  * Removing unnecessery parentheses, e.g. '1+(2*3)' to '1+2*3'.
  * Constant folding, e.g. '1+(2*3)' to '7'.
  * Concantenation of string literals, e.g. '"a"+"b"' to '"ab"', or
    '"a""b"' to '"ab"'.
  * Seprating expressions with ';' instead of newline + indent.
  * Any obfuscation.
  * Any general compression (such as Flate, LZMA, bzip2).

  Args:
    source: Python source code to minify. Can be str, buffer (or anything
      convertible to a buffer, e.g. bytearray), a readline method of a
      file-object or an iterable of line strs.
    output_func: Function which will be called with str arguments for each
      output piece.
  """
  if not isinstance(source, binary_type):
    raise TypeError
  elif isinstance(source, binary_type):
    if type(zip()) is not list:  # Python 3.
      import io
      source_str = str(source, 'ascii')
      source_func = lambda: io.StringIO(source_str).readline
    else:
      # This also works, except it's different at the end of the partial line:
      # source = iter(line + '\n' for line in str(buf).splitlines()).next
      import cStringIO
      source_str = source
      source_func = lambda: cStringIO.StringIO(source).readline
    if _NONASCII_RE.match(source_str):
      # TODO(pts): Repect -*- coding: ... -*-.
      raise ValueError('Source code is not ASCII.')
    source = source_func()
  elif not callable(source):
    # Treat source as an iterable of lines. Add trailing '\n' if needed.
    source = iter(
        line + '\n' * (not line.endswith('\n')) for line in source).next

  _COMMENT, _NL = COMMENT, NL  # tokenize.*
  _NAME, _NUMBER, _STRING = NAME, NUMBER, STRING  # token.*
  _NEWLINE, _INDENT, _DEDENT = NEWLINE, INDENT, DEDENT  # token.*
  _COMMENT_OR_NL = (_COMMENT, _NL)
  _NAME_OR_NUMBER = (_NAME, _NUMBER)

  i = 0  # Indentation.
  is_at_bol = is_at_bof = 1  # Beginning of line and file.
  is_empty_indent = 0
  pt, ps = -1, ''  # Previous token.
  # There are small differences in tokenize.generate_tokens in Python
  # versions, but they don't affect us, so we don't care:
  # * In Python <=2.4, the final DEDENTs and ENDMARKER are not yielded.
  # * In Python <=2.5, the COMMENT ts contains the '\n', and a separate
  #   NL is not generated.
  for tt, ts, _, _, _ in generate_tokens(source):  # tokenize.*
    if tt == _INDENT:
      i += 1
      is_empty_indent = 1
    elif tt == _DEDENT:
      if is_empty_indent:
        output_func(' ' * i)  # TODO(pts): Merge with previous line.
        output_func('pass\n')
        is_empty_indent = 0
      i -= 1
    elif tt == _NEWLINE:
      if not is_at_bol:
        output_func('\n')
      is_at_bol, pt, ps = 1, -1, ''
    elif (tt == _STRING and is_at_bol or  # Module-level docstring etc.
          tt in _COMMENT_OR_NL):
      # TODO(pts): Don't remove this from the begnning of the line: ''.hex.
      pass
    else:
      if is_at_bol:
        output_func(' ' * i)
        is_at_bol = is_at_bof = 0
      if pt in _NAME_OR_NUMBER and (tt in _NAME_OR_NUMBER or
          (tt == _STRING and ts[0] in 'rb')):
        output_func(' ')
      output_func(ts)
      pt, ps, is_empty_indent = tt, ts, 0
  if is_empty_indent:
    output_func(' ' * i)
    output_func('pass\n')


# We could support \r and \t outside strings, minify_str would remove them.
UNSUPPORTED_CHARS_RE = re.compile(b(r'[^\na -~]+'))


def minify_file(file_name, code_orig):
  i = code_orig.find(b('\n'))
  if i >= 0:
    line1 = code_orig[:i]
    if b('-*- coding: ') in line1:
      # We could support them by keeping this comment, but instead we opt
      # for fully ASCII Python input files.
      raise ValueError('-*- coding declarations not supported.')
  match = UNSUPPORTED_CHARS_RE.search(code_orig)
  if match:
    raise ValueError('Unsupported chars in source: %r' % match.group(0))
  if sys.version_info[:2] < (2, 6):
    fix = SyntaxFixer._fix
  else:
    fix = lambda data: data
  compile(fix(code_orig), file_name, 'exec')  # Check for syntax errors.
  output = []
  minify_str(code_orig, output.append)
  code_mini = ''.join(output)
  compile(fix(code_mini), file_name, 'exec')  # Check for syntax errors.
  return code_mini


# Run this script with a specific version of Python (including 2.4 and 2.5)
# like this:
#
#   $ python2.4 -c"import sys;del sys.argv[0];sys.path[0]=sys.argv[0];import m" tinygpgs.single
#
# Unfortunately the shorthad `python2.4 tinygpgs.single' is impossible,
# because it's impossible to avoid a Python SyntaxError in the ZIP (PK\3\4)
# segment. There is no Python equivalent of __END__.
SCRIPT_PREFIX = b(r'''#!/bin/sh --
#
# tinygpgs: symmetric key encryption tool compatible with GPG
#
# This script works with Python >=2.4, including Python 3.
# The shell script below tries to find such an interpreter and then runs it.
#
# If you have Python >=2.6, you can also run it directly with
# Python, otherwise you have to run it as a shell script.
#

P="$(readlink "$0" 2>/dev/null)"
test "$P" && test "${P#/}" = "$P" && P="${0%/*}/$P"
test "$P" || P="$0"
type python    >/dev/null 2>&1 && exec python -c"import sys;del sys.argv[0];sys.path[0]=sys.argv[0];import m" "$P" ${1+"$@"}
type python3   >/dev/null 2>&1 && exec python3   -- "$P" ${1+"$@"}
type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$P" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$P" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && exec python2.5 -c"import sys;del sys.argv[0];sys.path[0]=sys.argv[0];import m" "$P" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && exec python2.4 -c"import sys;del sys.argv[0];sys.path[0]=sys.argv[0];import m" "$P" ${1+"$@"}
echo "fatal: Python interpreter not found for: $0" >&2;exit 1

''')

M_CODE = b(r'''if (2, 4) <= __import__('sys').version_info[:2] < (2, 6):
  __import__('tinygpgs.f')
__import__('tinygpgs.__main__')
''')

def new_zipinfo(file_name, file_mtime, permission_bits=int('0644', 8)):
  zipinfo = zipfile.ZipInfo(file_name, file_mtime)
  zipinfo.external_attr = (int('0100000', 8) | (permission_bits & int('07777', 8))) << 16
  return zipinfo


def main(argv):
  os.chdir(os.path.dirname(__file__) or '.')
  assert os.path.isfile('lib/tinygpgs/main.py')
  zip_output_file_name = 't.zip'
  single_output_file_name = 'tinygpgs.single'
  try:
    os.remove(zip_output_file_name)
  except OSError:
    pass

  time_now = time.localtime()[:6]
  py_files = ['tinygpgs/%s' % entry for entry in os.listdir('lib/tinygpgs') if entry.endswith('.py')]

  zf = zipfile.ZipFile(zip_output_file_name, 'w', zipfile.ZIP_DEFLATED)
  try:
    for file_name in py_files:
      assert not file_name.endswith('/m.py')
      code_orig = open('lib/' + file_name, 'rb').read()
      # The zip(1) command also uses localtime. The ZIP file format doesn't
      # store the time zone.
      file_mtime = time.localtime(os.stat('lib/' + file_name).st_mtime)[:6]
      code_mini = minify_file(file_name, code_orig)
      # Compression effort doesn't matter, we run advzip below anyway.
      zf.writestr(new_zipinfo(file_name, file_mtime), code_mini)
      del code_orig, code_mini  # Save memory.
    zf.writestr(new_zipinfo('m.py', time_now), M_CODE)
    zf.writestr(new_zipinfo('__main__.py', time_now), 'import m')
  finally:
    zf.close()

  exit_code = subprocess.call(('advzip', '-qz4', '--', zip_output_file_name))
  if exit_code:
    sys.exit('fatal: advcip failed with exit_code=%d' % exit_code)

  f = open(zip_output_file_name, 'rb')
  try:
    data = f.read()
  finally:
    f.close()
  os.remove(zip_output_file_name)

  f = open(single_output_file_name, 'wb')
  try:
    f.write(SCRIPT_PREFIX)
    f.write(data)
  finally:
    f.close()

  os.chmod(single_output_file_name, int('0755', 8))

  sys.stderr.write(
      'info: created %s (%d bytes)\n' %
      (single_output_file_name, os.stat(single_output_file_name).st_size))


if __name__ == '__main__':
  sys.exit(main(sys.argv))
