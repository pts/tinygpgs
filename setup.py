from distutils.core import setup
import sys

if sys.version_info < (2,4):
  sys.exit('Sorry, Python <2.4 is not supported.')
if sys.version_info >= (3,):
  sys.exit('Sorry, Python >=3 is not supported.')

setup(
    name='tinygpgs',
    version='0.1',  # TODO(pts): Autogenerate.
    author='pts',
    author_email='pts@fazekas.hu',
    packages=['tinygpgs'],
    package_dir={'': 'lib'},
    url='https://github.com/pts/tinygpgs',
    license='LICENSE.txt',
    description='symmetric key encryption and decryption compatible with GPG',
    long_description=open('tinygpgs.rst', 'rb').read(),
    # extras_require is a setuptools feature, it's a no-op here.
    extras_require={'fast': ['pycrypto (>= 2.6)']},
    # Optional, but strongly recommended for speed.
    #requires=['pycrypto (>= 2.6)'],
    requires=[],
)
