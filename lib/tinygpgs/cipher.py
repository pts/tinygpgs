"""Pure Python (slow) implementation of OpenPGP ciphers.

Use PyCrypto.Cipher._* for faster implementations.
"""

import struct

from tinygpgs.strxor import make_strxor

# --- AES block cipher.
#
# Pure Python code based on from CryptoPlus (2014-11-17):
# https://github.com/doegox/python-cryptoplus/commit/a5a1f8aecce4ddf476b2d80b586822d9e91eeb7d
#
# TODO(pts): Is this faster? https://github.com/DonggeunKwon/aes/blob/master/aes/aes.py
#

class AES(object):
  """AES cipher. Slow, but compatible with Crypto.Cipher.AES.new and
  aes.Keysetup.

  Usage:

    ao = SlowAes('key1' * 8)
    assert len(ao.encrypt('plaintext_______')) == 16
    assert len(ao.decrypt('ciphertext______')) == 16
  """

  # --- Initialize the following constants: S, Si, T1, T2, T3, T4, T5, T6, T7, T8, U1, U2, U3, U4, RC.
  #
  # Hardcoding the final values would make the code 14 kB longer.

  # Produce log and alog tables, needed for multiplying in the
  # field GF(2^m) (generator = 3).
  alog = [1]
  for i in xrange(255):
    j = (alog[-1] << 1) ^ alog[-1]
    if j & 0x100 != 0:
      j ^= 0x11B
    alog.append(j)

  log = [0] * 256
  for i in xrange(1, 255):
    log[alog[i]] = i

  # multiply two elements of GF(2^m)
  def mul(a, b, alog, log):
    return a and b and alog[(log[a & 255] + log[b & 255]) % 255]

  # Substitution box based on F^{-1}(x).
  box = [[0] * 8 for i in xrange(256)]
  box[1][7] = 1
  for i in xrange(2, 256):
    j = alog[255 - log[i]]
    for t in xrange(8):
      box[i][t] = (j >> (7 - t)) & 0x01

  A = ((1, 1, 1, 1, 1, 0, 0, 0), (0, 1, 1, 1, 1, 1, 0, 0), (0, 0, 1, 1, 1, 1, 1, 0), (0, 0, 0, 1, 1, 1, 1, 1), (1, 0, 0, 0, 1, 1, 1, 1), (1, 1, 0, 0, 0, 1, 1, 1), (1, 1, 1, 0, 0, 0, 1, 1), (1, 1, 1, 1, 0, 0, 0, 1))
  B = (0, 1, 1, 0, 0, 0, 1, 1)

  # Affine transform:  box[i] <- B + A*box[i].
  cox = [[0] * 8 for i in xrange(256)]
  for i in xrange(256):
    for t in xrange(8):
      cox[i][t] = B[t]
      for j in xrange(8):
        cox[i][t] ^= A[t][j] * box[i][j]

  # S-boxes and inverse S-boxes.
  S, Si =  [0] * 256, [0] * 256
  for i in xrange(256):
    S[i] = cox[i][0] << 7
    for t in xrange(1, 8):
      S[i] ^= cox[i][t] << (7 - t)
    Si[S[i] & 255] = i

  # T-boxes.
  G = ((2, 1, 1, 3), (3, 2, 1, 1), (1, 3, 2, 1), (1, 1, 3, 2))
  AA = [[0] * 8 for i in xrange(4)]
  for i in xrange(4):
    for j in xrange(4):
      AA[i][j] = G[i][j]
      AA[i][i + 4] = 1

  for i in xrange(4):
    pivot = AA[i][i]
    if pivot == 0:
      t = i + 1
      while AA[t][i] == 0 and t < 4:
        t += 1
        assert t != 4, 'G matrix must be invertible.'
        for j in xrange(8):
          AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
        pivot = AA[i][i]
    for j in xrange(8):
      if AA[i][j] != 0:
        AA[i][j] = alog[(255 + log[AA[i][j] & 255] - log[pivot & 255]) % 255]
    for t in xrange(4):
      if i != t:
        for j in xrange(i + 1, 8):
          AA[t][j] ^= mul(AA[i][j], AA[t][i], alog, log)
        AA[t][i] = 0

  iG = [[0] * 4 for i in xrange(4)]
  for i in xrange(4):
    for j in xrange(4):
      iG[i][j] = AA[i][j + 4]

  def mul4(a, bs, mul, alog, log):
    r = 0
    if a:
      for b in bs:
        r <<= 8
        if b:
          r |= mul(a, b, alog, log)
    return r

  T1, T2, T3, T4, T5, T6, T7, T8, U1, U2, U3, U4 = [], [], [], [], [], [], [], [], [], [], [], []
  for t in xrange(256):
    s = S[t]
    T1.append(mul4(s, G[0], mul, alog, log))
    T2.append(mul4(s, G[1], mul, alog, log))
    T3.append(mul4(s, G[2], mul, alog, log))
    T4.append(mul4(s, G[3], mul, alog, log))
    s = Si[t]
    T5.append(mul4(s, iG[0], mul, alog, log))
    T6.append(mul4(s, iG[1], mul, alog, log))
    T7.append(mul4(s, iG[2], mul, alog, log))
    T8.append(mul4(s, iG[3], mul, alog, log))
    U1.append(mul4(t, iG[0], mul, alog, log))
    U2.append(mul4(t, iG[1], mul, alog, log))
    U3.append(mul4(t, iG[2], mul, alog, log))
    U4.append(mul4(t, iG[3], mul, alog, log))

  RC = [1]  # Round constants.
  r = 1
  for t in xrange(1, 30):
    r = mul(2, r, alog, log)
    RC.append(r)

  del A, AA, pivot, B, G, box, log, alog, i, j, r, s, t, mul, mul4, cox, iG

  # --- End of constant initialization.

  __slots__ = ('Ke', 'Kd')

  def __init__(self, key):
    if len(key) not in (16, 24, 32):
      raise ValueError('Invalid AES key size: ' + str(len(key)))
    RC, S, U1, U2, U3, U4 = self.RC, self.S, self.U1, self.U2, self.U3, self.U4
    ROUNDS = 6 + (len(key) >> 2)
    Ke = [[0] * 4 for i in xrange(ROUNDS + 1)]  # Encryption round keys.
    Kd = [[0] * 4 for i in xrange(ROUNDS + 1)]  # Decryption round keys.
    RKC = 28 + len(key)  # Round key count.
    KC = len(key) >> 2
    tk = list(struct.unpack('>' + 'L' * KC, key))
    # Copy values into round key arrays.
    t = 0
    while t < KC:
      Ke[t >> 2][t & 3] = tk[t]
      Kd[ROUNDS - (t >> 2)][t & 3] = tk[t]
      t += 1
    tt = ri = 0
    while t < RKC:
      # Extrapolate using phi (the round key evolution function).
      tt = tk[KC - 1]
      tk[0] ^= ((S[(tt >> 16) & 255] & 255) << 24 ^ (S[(tt >> 8) & 255] & 255) << 16 ^ (S[tt & 255] & 255) <<  8 ^ (S[(tt >> 24) & 255] & 255) ^ (RC[ri] & 255) << 24)
      ri += 1
      if KC != 8:
        for i in xrange(1, KC):
          tk[i] ^= tk[i - 1]
      else:
        for i in xrange(1, KC >> 1):
          tk[i] ^= tk[i-1]
        tt = tk[(KC >> 1) - 1]
        tk[KC >> 1] ^= ((S[tt & 255] & 255) ^ (S[(tt >>  8) & 255] & 255) << 8 ^ (S[(tt >> 16) & 255] & 255) << 16 ^ (S[(tt >> 24) & 255] & 255) << 24)
        for i in xrange((KC >> 1) + 1, KC):
          tk[i] ^= tk[i - 1]
      # Copy values into round key arrays.
      j = 0
      while j < KC and t < RKC:
        Ke[t >> 2][t & 3] = tk[j]
        Kd[ROUNDS - (t >> 2)][t & 3] = tk[j]
        j += 1
        t += 1
    # Invert MixColumn where needed.
    for r in xrange(1, ROUNDS):
      for j in xrange(4):
        tt = Kd[r][j]
        Kd[r][j] = (U1[(tt >> 24) & 255] ^ U2[(tt >> 16) & 255] ^ U3[(tt >>  8) & 255] ^ U4[tt & 255])
    self.Ke, self.Kd = Ke, Kd

  def encrypt(self, plaintext):
    Ke, S, T1, T2, T3, T4 = self.Ke, self.S, self.T1, self.T2, self.T3, self.T4
    if len(plaintext) != 16:
      raise ValueError('Wrong block length, expected 16, got: ' + str(len(plaintext)))
    ROUNDS = len(Ke) - 1
    t = struct.unpack('>LLLL', plaintext)
    Ker = Ke[0]
    t = [t[i] ^ Ker[i] for i in xrange(4)] * 2
    for r in xrange(1, ROUNDS):  # Apply round transforms.
      Ker = Ke[r]
      t = [T1[(t[i] >> 24) & 255] ^ T2[(t[i + 1] >> 16) & 255] ^ T3[(t[i + 2] >> 8) & 255] ^ T4[ t[i + 3] & 255] ^ Ker[i] for i in xrange(4)] * 2
    Ker = Ke[ROUNDS]
    return struct.pack('>LLLL', *((S[(t[i] >> 24) & 255] << 24 | S[(t[i + 1] >> 16) & 255] << 16 | S[(t[i + 2] >> 8) & 255] << 8 | S[t[i + 3] & 255]) ^ Ker[i] for i in xrange(4)))

  def decrypt(self, ciphertext):
    Kd, Si, T5, T6, T7, T8 = self.Kd, self.Si, self.T5, self.T6, self.T7, self.T8
    if len(ciphertext) != 16:
      raise ValueError('Wrong block length, expected 16, got: ' + str(len(plaintext)))
    ROUNDS = len(Kd) - 1
    t = struct.unpack('>LLLL', ciphertext)
    Kdr = Kd[0]
    t = [t[i] ^ Kdr[i] for i in xrange(4)] * 2
    for r in xrange(1, ROUNDS):  # Apply round transforms.
      Kdr = Kd[r]
      t = [T5[(t[i] >> 24) & 255] ^ T6[(t[i + 3] >> 16) & 255] ^ T7[(t[i + 2] >> 8) & 255] ^ T8[ t[i + 1] & 255] ^ Kdr[i] for i in xrange(4)] * 2
    Kdr = Kd[ROUNDS]
    return struct.pack('>LLLL', *((Si[(t[i] >> 24) & 255] << 24 | Si[(t[i + 3] >> 16) & 255] << 16 | Si[(t[i + 2] >> 8) & 255] << 8 | Si[t[i + 1] & 255]) ^ Kdr[i] for i in xrange(4)))


# --- Blowfish block cipher.
#
# Based on: https://github.com/doegox/python-cryptoplus/blob/a5a1f8aecce4ddf476b2d80b586822d9e91eeb7d/src/CryptoPlus/Cipher/pyblowfish.py
#


def _blowfish_crypt(pr_boxes, s_boxes, l, r):
  for i in xrange(16):
    l ^= pr_boxes[i]
    r ^= ((((s_boxes[0][(l >> 24) & 255] + s_boxes[1][(l >> 16) & 255]) & 0xffffffff) ^ s_boxes[2][(l >> 8) & 255]) + s_boxes[3][l & 255]) & 0xffffffff
    l, r = r, l
  return r ^ pr_boxes[17], l ^ pr_boxes[16]


def _blowfish_keysetup(key, _blowfish_crypt=_blowfish_crypt, _unpack=struct.unpack):
  if not 8 <= len(key) <= 56:
    raise ValueError('Blowfish key size must be between 8 and 56, got: %d' % len(key))
  if len(key) < 8 or len(key) > 56:
    raise ValueError, "Invalid cipher key length: %s" %len(key)
  # Copy, because we modify p_boxes and s_boxes later.
  p_boxes = list((0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89, 0x452821e6,
                  0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b))
  S0 = (0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
        0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
        0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
        0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
        0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6,
        0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
        0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
        0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
        0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
        0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
        0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
        0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
        0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd,
        0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
        0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8, 0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
        0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
        0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b, 0x9a53e479, 0xb6f84565,
        0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
        0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64,
        0x8888b812, 0x900df01c, 0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
        0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
        0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf, 0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
        0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af, 0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f,
        0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
        0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6,
        0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a)
  S1 = (0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266, 0xecaa8c71, 0x699a17ff,
        0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
        0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1, 0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9,
        0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
        0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9, 0x7ca92ff6,
        0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7, 0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
        0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331, 0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79,
        0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
        0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908,
        0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
        0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509, 0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1,
        0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
        0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960, 0x5223a708, 0xf71312b6,
        0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
        0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84, 0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96,
        0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
        0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7, 0x9b540b19, 0x875fa099,
        0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
        0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea,
        0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
        0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646,
        0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285, 0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
        0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061, 0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460,
        0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
        0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340, 0xc5c43465, 0x713e38d8,
        0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7)
  S2 = (0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068, 0xd4082471, 0x3320f46a,
        0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
        0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4,
        0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
        0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b, 0x1dc9faf7, 0x4b6d1856,
        0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
        0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b, 0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9,
        0x5ef47e1c, 0x9029317c, 0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
        0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564, 0x257b7834, 0x602a9c60,
        0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
        0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728, 0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa,
        0xc39dfd27, 0xf33e8d1e, 0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
        0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c,
        0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
        0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa,
        0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
        0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc, 0x83426b33, 0xf01eab71,
        0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
        0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770,
        0x8cd55591, 0xc902de4c, 0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
        0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169, 0xdcb7da83, 0x573906fe,
        0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027, 0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
        0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62, 0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de,
        0xebfc7da1, 0xce591d76, 0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
        0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4,
        0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0)
  S3 = (0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe, 0xd5118e9d, 0xbf0f7315,
        0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
        0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6, 0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a,
        0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
        0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59, 0x80e4a915, 0x87b08601,
        0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
        0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc,
        0xf8d56629, 0x79132e28, 0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
        0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5,
        0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f, 0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
        0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224,
        0x69852dfd, 0x09072166, 0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
        0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e,
        0xaec2771b, 0xf64e6370, 0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
        0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048, 0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc,
        0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
        0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f, 0xf79e59b7, 0x43f5bb3a,
        0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
        0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df,
        0xd3a0342b, 0x8971f21e, 0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
        0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623,
        0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc, 0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
        0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222,
        0xb6cbcf7c, 0xcd769c2b, 0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
        0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0,
        0x3f09252d, 0xc208e69f, 0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6)
  s_boxes = (list(S0), list(S1), list(S2), list(S3))
  for i, val in enumerate(_unpack('>18L', (key * (72 // len(key) + 1))[:72])):
    p_boxes[i] ^= val
  l, r = 0, 0
  for i in xrange(0, 18, 2):
    p_boxes[i], p_boxes[i + 1] = l, r = _blowfish_crypt(p_boxes, s_boxes, l, r)
  for i in xrange(4):
    for j in xrange(0, 256, 2):
      s_boxes[i][j], s_boxes[i][j + 1] = l, r = _blowfish_crypt(p_boxes, s_boxes, l, r)
  return p_boxes, s_boxes


class Blowfish(object):
  """Blowfish block cipher."""

  block_size = 8
  key_size = 56  # Key size can vary between 8 and 56 bytes.

  __slots__ = ('_pb', '_rb', '_sb')

  def __init__(self, key, _blowfish_crypt=_blowfish_crypt, _blowfish_keysetup=_blowfish_keysetup):
    self._pb, self._sb = _blowfish_keysetup(key)
    self._rb = self._pb[::-1]  # For speed in _blowfish_crypt.

  def encrypt(self, block, _blowfish_crypt=_blowfish_crypt, _pack=struct.pack, _unpack=struct.unpack):
    if len(block) != 8:
      raise ValueError('Blowfish block size must be 8, got: %d' % len(block))
    # Big endian, most users need that.
    return _pack('>LL', *_blowfish_crypt(self._pb, self._sb, *_unpack('>LL', block)))

  def decrypt(self, block, _blowfish_crypt=_blowfish_crypt, _pack=struct.pack, _unpack=struct.unpack):
    if len(block) != 8:
      raise ValueError('Blowfish block size must be 8, got: %d' % len(block))
    return _pack('>LL', *_blowfish_crypt(self._rb, self._sb, *_unpack('>LL', block)))


del _blowfish_keysetup, _blowfish_crypt


# --- CAST5 (CAST-128) block cipher with 128-bit key.
#
# Based on CAST5_PP.pm 1.04 in https://metacpan.org/pod/Crypt::CAST5_PP .
#


class CAST(object):
  """CAST5 (CAST-128) cipher with 128-bit key. Slow, but compatible with
  Crypto.Cipher.CAST.new.

  Block size is 8 bytes, key size is 16 bytes (128 bits).

  Using `CAST' as the class name to match Crypto.Cipher._CAST.
  """

  S = tuple(struct.unpack('>256L', s.decode('hex')) for s in
            ('30fb40d49fa0ff0b6beccd2f3f258c7a1e213f2f9c004dd36003e540cf9fc949bfd4af2788bbbdb5e203409098d096756e63a0e015c361d2c2e7661d22d4ff8e28683b6fc07fd059ff2379c8775f50e243c340d3df2f8656887ca41aa2d2bd2da1c9e0d6346c481961b76d8722540f2f2abe32e1aa54166b22568e3aa2d341d066db40c8a784392f004dff2f2db9d2de97943fac4a97c1d8527644b7b5f437a7b82cbaefd751d1596ff7f0ed5a097a1f827b68d090ecf52e22b0c054bc8e59354b6d2f7f50bb64a2d2664910bee5812db7332290e93b159fb48ee4114bff345dfd45c240ad31973fc4f6d02e55fc8165d5b1caada1ac2daea2d4b76dc19b0c50882240f20c6e4f38a4e4bfd74f5ba272564c1d2fc59c5319b949e354b04669feb1b6ab8ac71358dd6385c545110f935d57538ad56a390493e63d37e02a54f6b33a787d5f6276a0b519a6fcdf7a42206a29f9d4d5f61b1891bb72275eaa50816738901091c6b505eb84c7cb8c2ad75a0f874a1427a2d1936b2ad286afaa56d291d7894360425c750d93b39e26187184c96c00b32d73e2bb14a0bebc3c5462377964459eab3f328b827718cf8259a2cea604ee002e89fe78e63fab0950325ff6c281383f056963c5c876cb5ad6d49974c9ca180dcf380782d5c7fa5cf68ac3151135e79e1347da91d0f40f9086a7e2419e31366241051ef495aa573b044a805d8d548300d000322a3cbf64cddfba57a68e75c6372b50afd341a7c13275915a0bf56b54bfab2b0b1426ab4cc9d7449ccd82f7fbf265ab85c5f31b55db94aad4e324cfa4bd3f2deaa3e29e204d02c8bd25aceadf55b3d5bd9e98e31231b22ad5ad6c954329deadbe4528d8710f69aa51c90faa786bf622513f1eaa51a79b2ad344cc7b5a41f0d37cfbad1b06950541ece491b4c332e6032268d4c9600accce387e6dbf6bb16c6a70fb780d03d9c9d4df39dee01063da4736f4645ad328d8b347cc9675bb0fc398511bfb4ffbcc35b58bcf6ae11f0abcbfc5fe4aa70aec10ac39570a3f04442f6188b153e0397a2e5727cb799ceb418f1cacd68d2ad37c960175cb9dc69dff09c75b65f0d9db40d8ec0e77794744ead4b11c3274dd24cb9e7e1c54bdf01144f9d2240eb19675b3fda3ac3755d47c27af51c85f4d56907596a5bb15e6580304f0ca042cf1011a37ea8dbfaadb35ba3e4a3526ffa0c37b4d09bc306ed998a526665648f725ff5e569d0ced63d07c63b2cf700b45e1d5ea50f185a92872af1fbda7d4234870a7870bf32d3b4d7942e041980cd0ede726470db8f881814c474d6ad77c0c5e5cd1231959381b7298f5d2f4dbab8386536e2f1e2383719c9ebd91e0469a56456edc39200c20c8c571962bda1ce1e696ffb141ab087cca89b91a69e78302cc4843a2f7c579429ef47d427b169c5ac9f049dd8f0f005c8165bf',
             '1f201094ef0ba75b69e3cf7e393f4380fe61cf7aeec5207a55889c9472fc0651ada7ef794e1d7235d55a63cede0436ba99c430ef5f0c079418dcdb7da1d6eff3a0b52f7b59e83605ee15b094e9ffd909dc440086ef944459ba83ccb3e0c3cdfbd1da41813b092ab1f997f1c1a5e6cf7b01420ddbe4e7ef5b25a1ff41e180f8061fc41080179bee7ad37ac6a9fe5830a498de8b7f77e83f4e7992926924fa9f7be113c85bacc40083d7503525f7ea615f621431540d554b635d681121c866c3593d63cf73cee234c0d4d87e875c672b21071f618139f7627f361e3084e4eb573b602f64a4d63acd9c1bbc46359e81032d2701f50c99847ab4a0e3df79ba6cf38c108430942537a95ef46f6ffea1ff3b1f208cfb6a8f458c74d9e0a2274ec73a34fc884f693e4de8dfef0e00883559648d8a45388c1d804366721d9bfda58684bbe8256333844e8212128d8098fed33fb4ce280ae127e19ba5d5a6c252e49754bdc5d655ddeb66706477840b4da1b6a80184db26a9e0b5671421f043b7e5d0586054f03084066ff472a31aa153dadc4755b5625dbf68561be683ca6b942d6ed23beccf01dba6d3d0bab6803d5caf77a70933b4a34c397bc8d65ee22b955f0e530481ed6f6120e74364b45e1378de18639b881ca122b96726d18049a7e822b7da7b5e552d255272d23779d2951cc60d894c488cb4021ba4fe5ba4b09f6b1ca815cfa20c30058871df63b9de2fcb0cc6c9e90beeff53e3214517b45428359f63293cee41e7296e1d2d7c500452861e6685f3f33401c630a22c9531a7085060930f1373f98417a1269859ec645c4452c877a9cdff33a6a02b17417cbad9a22180036f50d99c08cb3f4861c26bd76564a3f6ab8034267625a75e7be4e6d1fc20c710e6cdf0b68017844d3b31eef84d7e0824e42ccb49eb846a3bae8ff77888ee5d60f67af756732fdd5cdba11631c130f66f43b3faec54157fd7faef8579ccd152de58db2ffd5e8f32ce19306af97a02f03ef899319ad5c242fa0fa7e3ebb0c68e4906b8da230c80823028dcdef3c8d35fb171088a1bc8bec0c56061a3c9e8bca8f54dc72feffa22822e9982c570b4d8d94e898b1c34bc301e16e6273be979b0ffeaa661d9b8c600b24869b7ffce3f08dc283b43daf65af7e197987619b72f8f1c9ba4dc8637a016a7d3b19fc393b7a7136eebc6bcc63e1a513742ef6828bc520365d62d6a77ab3527ed4b821fd216095c6e2edb92f2fb5eea29cb145892f591584f7f5483697b2667a8cc851960488c4bacea833860d40d23e0f96c387e8a0ae6d249b284600cd835731ddcb1c647ac4c56ea3ebd81b3230eabb06438bc87f0b5b1fa8f5ea2b3fc1846420a036b7a4fb089bd649da589a345415e5c0383233e5d3bb943d795727e6dd07c06dfdf1e6c6cc4ef7160a53973bfbe70838776054523ecf1',
             '8defc24025fa5d9feb903dbfe810c90747607fff369fe44b8c1fc644aececa90beb1f9bfeefbcaeae8cf195051df07ae920e8806f0ad0548e13c8d83927010d511107d9f07647db9b2e3e4d43d4f285eb9afa820fade82e0a067268b8272792e553fb2c0489ae22bd4ef9794125e3fbc21fffcee825b1bfd9255c5ed1257a2404e1a8302bae07fff528246e78e57140e3373f7bf8c9f8188a6fc4ee8c982b5a5a8c01db7579fc26467094f31f2bd3f5f40fff7c11fb78dfc8e6bd2c1437be59b99b03dbfb5dbc64b638dc0e655819d99a197c81c4a012d6ec5884a28ccc36f71b843c2136c0743f18309893c0feddd5f2f7fe850d7c07f7e02507fbf5afb9a04a747d2d01651192eaf70bf3e58c313805f98302e727cc3c40a0fb4020f7fef828c96fdad5d2c2aae8ee99a4950da88b88427f4a01eac5790796fb4498252dc15efbd7d9ba672597dada840d845f54504fa5d7403e83ec3054f91751a925669c223efe941a903f12e60270df20276e4b694fd6574927985b28276dbcb02778176f8af918d4e48f79e8f616ddfe29d840e842f7d83340ce5c896bbb68293b4b148ef303cab984faf28779faf9b92dc560d224d1e208437aa887d29dc962756d3dc8b907ceeb51fd240e7c07ce3e566b4a1c3e9615e3cf8209d6094d1e3cd9ca3415c76460e00ea983bd4d67881fd47572cf76cedd9bda8229c127dadaa438a074e1f97c090081bdb8a93a07ebeb938ca1597b03cff3dc2c0f88d1ab2ec64380e5168cc7bfbd90f2788124901815de5ffd4dd7ef86a76a2e214b9a40368925d958f4b39fffaba39aee9a4ffd30bfaf7933b6d498623193cbcfa27627545825cf47a61bd8ba0d11e42d1cead04f4127ea39210428db78272a9729270c4a8127de50b285ba1c83c62f44f35c0eaa5e805d231428929fbb4fcdf824fb66a530e7dc15b1f081fab108618aefcfd086df9ff2889694bcc11236a5cae12deca4d2c3f8cc5d2d02dfef8ef5896e4cf52da95155b67494a488cb9b6a80c5c8f82bc89d36b453a609437ec00c9a9447152530a874b49d773bc407c34671c02717ef64feb5536a2d02fffd2bf60c4d43f03c050b4ef6d07478cd1006e1888a2e53f55b9e6d4bca204801697573833d7207d67de0f8f3d72f87b33abcc4f337688c55d7b00a6b0947b0001570075d2f9bb88f88942019e4264a5ff856302e072dbd92bee971b696ea22fde5f08ae2baf7a616de5c98767cf1febd261efc8c2f1ac2571cc8239c267214cb8b1e583d1b7dc3e627f10bdcef90a5c380ff0443d606e6dc660543a495727c1482be98a1d8ab4173820e1be24af96da0f6845842599833be5600d457d282f93508334b362d91d11202b6d8da0642b1e319c305a0052bce6881b03588af7baefd54142ed9ca4315c1183323ec5dfef4636a133c501e9d3531cee353783',
             '9db304201fb6e9dea7be7befd273a2984a4f7bdb64ad8c5785510443fa020ed17e287affe60fb663095f35a179ebf120fd059d436497b7b1f3641f63241e4adf28147f5f4fa2b8cdc94300400cc32220fdd30b30c0a5374f1d2d00d924147b15ee4d111a0fca516771ff904c2d195ffe1a05645f0c13fefe081b08ca0517012180530100e83e5efeac9af4f87fe72701d2b8ee5f06df4261bb9e9b8a7293ea25ce84ffdff57188013dd64b04a26f263b7ed48400547eebe6446d4ca06cf3d6f52649abdfaea0c7f536338cc1503f7e93d377206111b638e172500e03f80eb2bbabe0502eec8d77de57971e81e14f6746c93354006920318f081dbb99ffc304a54d3518057f3d5ce3a6c866c65d5bcca9daec6fea9f926f919f46222f3991467da5bf6d8e1143c44f43958302d0214eeb022083b83fb6180c18f8931e281658e626486e3e8bd78a707477e4c1b506e07cf32d0a2579098b02e4eabb8128123b2369dead381574ca16df871b62211c40b7a51a9ef90014377b041e8ac809114003bd59e4d2e3d156d54fe876d52f91a340557be8de00eae4a70ce5c2ec4db4bba6e756bdffdd3369acec17b0350657232799afc8b056c8c3916b65811c5e1461196e85cb75be07c002c2325577893ff4ec5bbfc92dd0ec3b25b7801ab78d6d3b2420c763efc366a5fc9c3828800ace3205aac9548aeca1d7c7041afa321d16625a6701902c9b757a5431d477f79126b03136cc6fdbc70b8b46d9e66a4856e55a79026a4ceb52437eff2f8f76b40df980a58674cde3edda04eb17a9be042c18f4dfb7747f9dab2af7b4efc34d202e096b7c1741a254e5b6a035213d42f62c1c7c2661c2f50f6552daf9d2c231f825130f69d8167fa20418f2c8001a96a60d1526ab63315c215e0a72ec49bafefd187908d98d0dbd86311170a73e9b640ccc3e10d7d5cad3b60caec388f73001e16c728aff71eae2a11f9af36ecfcbd12fc1de8417ac07be6bcb44a1d88b9b0f56013988c3b1c52fcab4be31cdd878280612a3a4e26f7de53258fd7eb6d01ee90024adffc2f4990fc59711aac5001d7b9582e5e7d2109873f600613096c32d9521ada121ff299084157fbb977faf9eb3db29c9ed2a5ce2a465a730f32cd0aa3fe88a5cc091d49e2ce70ce454a9d60acd86015f191977079103dea03af678a8565edee356df21f05cbe8b75e387b3c50651b8a5c3efd8eeb6d2e523be77c21545292f69efdfafe67afbf470c4b2f3e0eb5bd6cc987639e4460c1fda85381987832fca007367a99144f8296b299e492fc2959266beabb5676e699bd3dddadf7e052fdb25701c1b5e51eef65324e66afce36c0316cc048644213eb7dc59d07965291fccd6fd4341823979932bcdf6b657c34d4edfd2827ae5290c3cb9536b851e20fe9833557e13ecf0b0d3ffb3723f85c5c10aef7ed2',
             '7ec90c042c6e74b99b0e66dfa6337911b86a7fff1dd358f544dd9d441731167f08fbf1fae7f511ccd2051b00735aba002ab722d8386381cbacf6243a69befd7ae6a2e77ff0c720cdc4494816ccf5c1803885164015b0a848e68b18cb4caadeff5f480a010412b2aa259814fc41d0efe24e40b48d248eb6fb8dba1cfe41a99b021a550a04ba8f65cb7251f4e795a51725c106ecd797a5980ac539b9aa4d79fe6af2f3f76368af8040ed0c9e5611b4958be1eb5a888709e6b0d7e071564e29fea76366e52d02d1c000c4ac8e059377f5710c05372a578535f22261be02d642a0c9df13a28074b55bd2682199c0d421e5ec53fb3ce8c8adedb328a87fc93d9599815c1ff900fe38d3990c4eff0b062407eaaa2f4fb14fb9697690c79505b0a8a774ef55a1ffe59ca2c2a6b62d27e66a4263df65001f0ec50966dfdd55bc29de0655911e739a17af897532c7911c89f894680d01e980524755f403b63cc90cc844b2bcf3f0aa87ac36e9e53a742601b3d82b1a9e744964ee2d7ecddbb1da01c94910b868bf800d26f3fd9342ede704a5c284636737b650f5b616f24766e38eca36c1136e05dbfef18391fb887a37d6e7f7d4c7fb7dc93063fcdfb6f589deec2941da26e46695b7566419f654efc5d08d58b748925401c1bacb7fe5ff550fb60830495bb5d0e887d72e5aab6a6ee1223a66cec62bf3cd9e0885f968cb3e47086c010fa21de820d18b69def3f65777fa02c3f6407edac3cbb3d5501793084db0d70eba0ab378d5d951fb0cded7da564124bbe494ca0b560f5755d1e0e1e56e6184b5be580a249f94f74bc0e327888e9f7b5561c3dc028005687715646c6bd744904db366b4f0a3c0f1648a697ed5af49e92ff6309e374f2cb6356a858085734991f84076f0ae02083be84d28421c9a44489406736e4cb8c10929108bc95fc67d869cf4134f616f2e77118db31b2be1aa90b4723ca5d7177d161bba9cad9010af462ba29fe459d245d34559d9f2da13dbc65487f3e4f94e176d486f097c13ea631da5c7445f7382175683f4cdc66a9770be0288b3cdcf726e5dd2f320936079459b80a5be60e2dba9c23101eba5315c224e42f21c5c1572f6721b2c1ad2fff38c25404e324ed72f4067b7fd0523138e5ca3bc78dc0fd66e75922283784d6b1758ebb16e44094f853f481d87fcfeae7b77b5ff768c2302bfaaf475565f46b02a2b0928013d38f5f70ca81f3652af4a8a66d5e7c0df3b0874950551101b5ad7a8f61ed5ad6cf6e47920758184d0cefa6588f7be584a0468260ff6f8f3a09c7f705346aba05ce96c28e176eda36bac307f376829d285360fa917e3fe2a24b79767f5a96b20d6cd259568ff1ebf7555442cf19f06bef9e0659aeeb9491d34010718bb30cab8e822fe1588570983750e6249da627e555e76ffa8b15345466d47de08efe9e7d4',
             'f6fa8f9d2cac6ce14ca34867e2337f7c95db08e7016843b4eced5cbc325553acbf9f0960dfa1e2ed83f0579d63ed86b91ab6a6b8de5ebe39f38ff7328989b13833f14961c01937bdf506c6dae4625e7ea308ea994e23e33c79cbd7cc48a14367a3149619fec94bd5a114174aeaa01866a084db2d09a8486fa888614a2900af9801665991e1992863c8f30c602e78ef3cd0d51932cf0fec14f7ca07d2d0a82072fd41197e9305a6b0e86be3da74bed3cd372da53c4c7f4448dab5d4406dba0ec3083919a79fbaeed949dbcfb04e670c535c3d9c0164bdb9412c0e636aba7dd9cdea6f7388e70bc76235f29adb5c4cdd8df0d48d8cb88153e208a198661ae2eac8284caf89aa9282239334be533b3a21bf16434be39aea3906efe8c36ef890cdd980226daec340a4a3df7e9c09a694a8075b7c5ecc221db3a69a69a02f68818a54ceb2296f53c0843afe89365525bfe68ab4628abccf222ebf25ac6f48a9a9938753bddb65e76ffbe7e967fd780ba935638e342bc1e8a11be94980740dc8087dfc8de4bf99a11101a07fd37975da5a26c0e81f994f9528cd89fd339fedb87834bf5f04456d22258698c9c4c83b2dc156be4f628daa57f55ec5e2220abed2916ebf4ec75b9524f2c3c042d15d99cd0d7fa07b6e27ffa8dc8af07345c106f41e232f35162386e6ea89263333b094157ec6f2372b74af692573e4e9a9d848f31602893a62ef1da787e238f3a5f67674364853209510634576698db6fad407592af95036f735234cfb6e877da4cec06c152daacb0396a8c50dfe5dfcd707ab0921c42f89dff0bb5fe2be78448f4f33754613c92b05d08d48b9d585dc049441c8098f9b7dede786c39a3373424100056a0917510ef3c8a6890072d628207682a9a9f7bebf32679dd45b5b75b353fd00cbb0e358830f220a1f8fb214d372cf08cc3c4a138cf63166061c87be88c98f886062e39747cf8e7ab6c852833cc2acfb3fc069764e8f025264d8314dda3870e31e665459c10908f0513021a56c5b68b7822f8aa03007cd3e74719eefdc872681073340d47e432fd90c5ec2418809286cf592d89108a930f6957ef305b7fbffbdc266e96f6fe4ac98b173ecc0bc60b42a953498dafba1ae122d4bd7360f25faaba4f3fcebe2969123257f0c3d9348af49361400bce8816f4a3814f200a3f940439c7a54c2bc704f57da41e7f9c25ad33a54f4a084b17f550559357cbeedbd15c87f97c5abba5ac7b5b6f6deaf3a479c3a5302da25653d7e6a54268d4951a477ea5017d55bd7d25d8844136c760404a8c8b8e5a121b81a928a60ed586997c55b96eaec991b2993591301fdb7f1088e8dfa9ab6f6f53b4cbf9f4a5de3abe6051d35a0e1d855d36b4cf1f544edebb0e93524bebb8fbda2d762cf49c92f5438b5f3317128a45448392905a65b1db8851c97bdd675cf2f',
             '85e04019332bf567662dbfffcfc656932a8d7f6fab9bc912de6008a12028da1f0227bce74d64291618fac30050f18b822cb2cb11b232e75c4b3695f2b28707dea05fbcf6cd4181e9e150210ce24ef1bdb168c381fde4e7895c79b0d81e8bfd434d49500138be4341913cee1d92a79c3f089766bebaeeadf41286becfb6eacb192660c2007565bde464241f7a8248dca9c3b3ad66281360860bd8dfa8356d1cf2107789beb3b2e9ce0502aa8f0bc0351e166bf52aeb12ff82e3486911d34d75164e7b3aff5f43671b9cf6e0374981ac83334266ce8c9341b7d0d854c0cb3a6c8847bc28294725ba37a66ad22b7ad61f1e0c5cbafa4437f107b6e7996242d2d8160a961288e1a5c06e13749e6772fc081ab1d139f7f9583745cf19df58bec3f756c06eba3007211b2445c28829c95e317fbc8ec51138bc46e9c6e6fa14bae8584aad4ebc46468f508b7829435ff124183b821dba9faff60ff4ea2c4e6d16e3926492544a8b009b4fc3aba68ced9ac96f7806a5b79ab2856e6e1aec3ca9be8386880e0804e955f1be56e7e5363bb3a1f25df7debb8561fe033c167462333c034c28da6d0c7479aac56c3ce4e1ad51f0c80298f8f35a1626a49feed82b291d382fe30c4fb99abb3257783ec6d97b6e77a6a9cb658b5cd45230c72bd1408b60c03eb7b9068d78a33754f4f430c87dc8a71302b96d8c32ebd4e7bebe8b9d2d7979fb06e72253088b75cf7711ef8da4e083c8588d6b786f5a6317a6fa5cf7a05dda0033f28ebfb0f5b9c310a0eac28008b9767aa3d9d2b079d34217021a718d9ac6336a2711fd60438050e3069908a83d7fedc4826d2bef4eeb8476488dcf2536c9d56628e74e41c2610aca3d49a9cfbae3b9dfb65f8de692aeaf643ac7d5e69ea80509f22b017da4173f70dd1e16c315e0d7f950b1b8872b9f4fd5625aba826a0179622ec01b9c15488aa9d716e74040055a2c93d29a22e32dbf9a058745b93453dc1ed699296e496cff6f1c9f4986dfe2ed07b87242d119de7eae053e561a15ad6f8c66626c1c7154c24cea082b2a93eb293917dcb0f058d4f2ae9ea294fb52cf564c9883fe662ec40581763953c301d6692ed3a0c108a1e7160ee4f2dfa6693ed285749046984c2b0edd4f7576565d393378a132234f3d321c5dc3f5e1944b269301c79f022f3c997e7e5e4f95043ffafbbd76f7ad0e296693f43d1fce6fc61e45bed3b5ab34f72bf9b71b0434c04e72b5675592a33db5229301cfd2a87f60aeb7671814386b30bcc33d38a0c07dfd1606f2c363519b589dd3905479f8e61cb8d64797fd61a9ea7759f42d57539d569a58cfe84e63ad462e1b786580f87ef381791491da55f440a230f3d1988f35b6e318d23ffa50bc3d40f021c3c0bdae4958c24c518f36b284b1d3700fedce83878ddadaf2a279c794e01be890716f4b954b8aa3',
             'e216300dbbddfffca7ebdabd356480957789f8b7e6c1121b0e241600052ce8b511a9cfb0e5952f11ece7990a9386d1742a42931c76e38111b12def3a37ddddfcde9adeb10a0cc32cbe19702984a00940bb243a0fb4d137cfb44e79f0049eedfd0b15a15d480d31688bbbde5a669ded42c7ece8313f8f95e772df191b7580330d940742515c7dcdfaabbe6d63aa402164b301d40a02e7d1ca53571dae7a3182a212a8ddecfdaa335d176f43e871fb46d438129022ce949ad4b84769ad965bd86282f3d05566fb976715b80b4e1d5b47a04cfde06fc28ec4b857e8726e647a78fc99865d44608bd5936c200e0339dc5ff65d0b00a3ae63aff27e8bd63270108c0cbbd350492998df04980cf42a9b6df4919e7edd530691854858cb7e073b74ef2e522fffb1d24708cc1c7e27cda4eb215b3cf1d2e219b47a38424f7618358560399d17dee727eb35e6c9aff67b36baf5b809c467cdc18910b1e11dbf7b06cd1af87170c6082d5e3354d4de495a64c6d006bcc0c62c3dd00db3708f8f3477d51b42264f620f24b8d2bf15c1b79e46a52564f8d7e54e3e3781607895cda5859c15a5e6459788c37bc75fdb07ba0c0676a3ab7f229b1e31842e7b24259fd7f8bef472835ffcb86df4c1f296f5b195fd0af0fcb0fe134ce2506d3d4f9b12eaf215f225a223736f9fb4c42825d0497934c713f8c4618187ea7a6e987cd16efc1436876cf1544107bedeee1456e9af27a04aa4413cf7c89992ecbae6dd67016d151682eba842eedffdba60b4f1907b7520e3030f24d8c29ee139673befa63fb871873054b6f2cf3b9f326442cb15a4ccb01a4504f1e47d8d844a1be5bae7dfdc42cbda70cd7dae0a57e85b7ad53f5af620cf4d8ccea4d42879d130a43486ebfb33d3cddc77853b5337effcb5c5068778e580b3e64e68b8f4c5c8b37e0d809ea2398feb7c132a4f9443b7950e2fee7d1c223613bddd06caa237df932bc4248289acf3ebc35715f6b7ef3478ddf267616fc148cbe49052815e5e410fabb48a24652eda7fa4e87b40e4e98ea0845889e9e1efd390fcdd07d35bdb48569438d7e5b257720101730edebc5b64311394917e4f503c2fba646f12827523d24ae0779695f9c17a8f7a5b2121d187b89629263a4dba510cdf81f47c9fad1163edea7b59651a00726e1140309200da6d774a0cdd61ad1f4603605bdfb09eedc36422ebe6a8cee7d28aa0e736a05564a6b910853209c7eb8f372de705ca8951570fdf09822bbd691a6caa12e4f287451c0fe0f6a27a3ada48194cf1764f0d771c2b67cdb156350d83845938fa0f42399ef336997b070e84093d4aa93e618360d87b1fa98b0c1149382ce97625a50614d1b70e25244b0c768347589e8d820d2059d1a466bb1ef8da0a8204f19130ba6e4ec0992651641ee7230d50b2ad80eaee68018db2a283ea8bf59e'))

  __slots__ = ('_ks',)

  def __init__(self, key):
    if len(key) != 16:
      raise ValueError('Invalid CAST5 key size: %d' % len(key))
    s, t, u, v = struct.unpack('>LLLL', key)
    s1, s2, s3, s4, s5, s6, s7, s8 = self.S
    ks = []
    for _ in xrange(2):
      w = s ^ s5[v >> 16 & 255] ^ s6[v & 255] ^ s7[v >> 24] ^ s8[v >> 8 & 255] ^ s7[u >> 24]
      x = u ^ s5[w >> 24] ^ s6[w >> 8 & 255] ^ s7[w >> 16 & 255] ^ s8[w & 255] ^ s8[u >> 8 & 255]
      y = v ^ s5[x & 255] ^ s6[x >> 8 & 255] ^ s7[x >> 16 & 255] ^ s8[x >> 24] ^ s5[u >> 16 & 255]
      z = t ^ s5[y >> 8 & 255] ^ s6[y >> 16 & 255] ^ s7[y & 255] ^ s8[y >> 24] ^ s6[u & 255]
      ks.append(s5[y >> 24] ^ s6[y >> 16 & 255] ^ s7[x & 255] ^ s8[x >> 8 & 255] ^ s5[w >> 8 & 255])
      ks.append(s5[y >> 8 & 255] ^ s6[y & 255] ^ s7[x >> 16 & 255] ^ s8[x >> 24] ^ s6[x >> 8 & 255])
      ks.append(s5[z >> 24] ^ s6[z >> 16 & 255] ^ s7[w & 255] ^ s8[w >> 8 & 255] ^ s7[y >> 16 & 255])
      ks.append(s5[z >> 8 & 255] ^ s6[z & 255] ^ s7[w >> 16 & 255] ^ s8[w >> 24] ^ s8[z >> 24])
      s = y ^ s5[x >> 16 & 255] ^ s6[x & 255] ^ s7[x >> 24] ^ s8[x >> 8 & 255] ^ s7[w >> 24]
      t = w ^ s5[s >> 24] ^ s6[s >> 8 & 255] ^ s7[s >> 16 & 255] ^ s8[s & 255] ^ s8[w >> 8 & 255]
      u = x ^ s5[t & 255] ^ s6[t >> 8 & 255] ^ s7[t >> 16 & 255] ^ s8[t >> 24] ^ s5[w >> 16 & 255]
      v = z ^ s5[u >> 8 & 255] ^ s6[u >> 16 & 255] ^ s7[u & 255] ^ s8[u >> 24] ^ s6[w & 255]
      ks.append(s5[s & 255] ^ s6[s >> 8 & 255] ^ s7[v >> 24] ^ s8[v >> 16 & 255] ^ s5[u >> 24])
      ks.append(s5[s >> 16 & 255] ^ s6[s >> 24] ^ s7[v >> 8 & 255] ^ s8[v & 255] ^ s6[v >> 16 & 255])
      ks.append(s5[t & 255] ^ s6[t >> 8 & 255] ^ s7[u >> 24] ^ s8[u >> 16 & 255] ^ s7[s & 255])
      ks.append(s5[t >> 16 & 255] ^ s6[t >> 24] ^ s7[u >> 8 & 255] ^ s8[u & 255] ^ s8[t & 255])
      w = s ^ s5[v >> 16 & 255] ^ s6[v & 255] ^ s7[v >> 24] ^ s8[v >> 8 & 255] ^ s7[u >> 24]
      x = u ^ s5[w >> 24] ^ s6[w >> 8 & 255] ^ s7[w >> 16 & 255] ^ s8[w & 255] ^ s8[u >> 8 & 255]
      y = v ^ s5[x & 255] ^ s6[x >> 8 & 255] ^ s7[x >> 16 & 255] ^ s8[x >> 24] ^ s5[u >> 16 & 255]
      z = t ^ s5[y >> 8 & 255] ^ s6[y >> 16 & 255] ^ s7[y & 255] ^ s8[y >> 24] ^ s6[u & 255]
      ks.append(s5[w & 255] ^ s6[w >> 8 & 255] ^ s7[z >> 24] ^ s8[z >> 16 & 255] ^ s5[y >> 16 & 255])
      ks.append(s5[w >> 16 & 255] ^ s6[w >> 24] ^ s7[z >> 8 & 255] ^ s8[z & 255] ^ s6[z >> 24])
      ks.append(s5[x & 255] ^ s6[x >> 8 & 255] ^ s7[y >> 24] ^ s8[y >> 16 & 255] ^ s7[w >> 8 & 255])
      ks.append(s5[x >> 16 & 255] ^ s6[x >> 24] ^ s7[y >> 8 & 255] ^ s8[y & 255] ^ s8[x >> 8 & 255])
      s = y ^ s5[x >> 16 & 255] ^ s6[x & 255] ^ s7[x >> 24] ^ s8[x >> 8 & 255] ^ s7[w >> 24]
      t = w ^ s5[s >> 24] ^ s6[s >> 8 & 255] ^ s7[s >> 16 & 255] ^ s8[s & 255] ^ s8[w >> 8 & 255]
      u = x ^ s5[t & 255] ^ s6[t >> 8 & 255] ^ s7[t >> 16 & 255] ^ s8[t >> 24] ^ s5[w >> 16 & 255]
      v = z ^ s5[u >> 8 & 255] ^ s6[u >> 16 & 255] ^ s7[u & 255] ^ s8[u >> 24] ^ s6[w & 255]
      ks.append(s5[u >> 24] ^ s6[u >> 16 & 255] ^ s7[t & 255] ^ s8[t >> 8 & 255] ^ s5[s & 255])
      ks.append(s5[u >> 8 & 255] ^ s6[u & 255] ^ s7[t >> 16 & 255] ^ s8[t >> 24] ^ s6[t & 255])
      ks.append(s5[v >> 24] ^ s6[v >> 16 & 255] ^ s7[s & 255] ^ s8[s >> 8 & 255] ^ s7[u >> 24])
      ks.append(s5[v >> 8 & 255] ^ s6[v & 255] ^ s7[s >> 16 & 255] ^ s8[s >> 24] ^ s8[v >> 16 & 255])
    for i in xrange(16, 32):
      ks[i] &= 31
    self._ks = tuple(ks)

  def encrypt(self, data):
    if len(data) != 8:
      raise ValueError('CAST5 block size must be 8, got: %d' % len(data))
    s1, s2, s3, s4, s5, s6, s7, s8 = self.S
    ks = self._ks
    l, r = struct.unpack('>LL', data)
    i = (ks[ 0] + r) & 0xffffffff; i = i << ks[16] | i >> (32 - ks[16]); l ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[ 1] ^ l) & 0xffffffff; i = i << ks[17] | i >> (32 - ks[17]); r ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[ 2] - r) & 0xffffffff; i = i << ks[18] | i >> (32 - ks[18]); l ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[ 3] + l) & 0xffffffff; i = i << ks[19] | i >> (32 - ks[19]); r ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[ 4] ^ r) & 0xffffffff; i = i << ks[20] | i >> (32 - ks[20]); l ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[ 5] - l) & 0xffffffff; i = i << ks[21] | i >> (32 - ks[21]); r ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[ 6] + r) & 0xffffffff; i = i << ks[22] | i >> (32 - ks[22]); l ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[ 7] ^ l) & 0xffffffff; i = i << ks[23] | i >> (32 - ks[23]); r ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[ 8] - r) & 0xffffffff; i = i << ks[24] | i >> (32 - ks[24]); l ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[ 9] + l) & 0xffffffff; i = i << ks[25] | i >> (32 - ks[25]); r ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[10] ^ r) & 0xffffffff; i = i << ks[26] | i >> (32 - ks[26]); l ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[11] - l) & 0xffffffff; i = i << ks[27] | i >> (32 - ks[27]); r ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[12] + r) & 0xffffffff; i = i << ks[28] | i >> (32 - ks[28]); l ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[13] ^ l) & 0xffffffff; i = i << ks[29] | i >> (32 - ks[29]); r ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[14] - r) & 0xffffffff; i = i << ks[30] | i >> (32 - ks[30]); l ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[15] + l) & 0xffffffff; i = i << ks[31] | i >> (32 - ks[31]); r ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    return struct.pack('>LL', r & 0xffffffff, l & 0xffffffff)

  def decrypt(self, data):
    if len(data) != 8:
      raise ValueError('CAST5 block size must be 8, got: %d' % len(data))
    s1, s2, s3, s4, s5, s6, s7, s8 = self.S
    ks = self._ks
    r, l = struct.unpack('>LL', data)
    i = (ks[15] + l) & 0xffffffff; i = i << ks[31] | i >> (32 - ks[31]); r ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[14] - r) & 0xffffffff; i = i << ks[30] | i >> (32 - ks[30]); l ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[13] ^ l) & 0xffffffff; i = i << ks[29] | i >> (32 - ks[29]); r ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[12] + r) & 0xffffffff; i = i << ks[28] | i >> (32 - ks[28]); l ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[11] - l) & 0xffffffff; i = i << ks[27] | i >> (32 - ks[27]); r ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[10] ^ r) & 0xffffffff; i = i << ks[26] | i >> (32 - ks[26]); l ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[ 9] + l) & 0xffffffff; i = i << ks[25] | i >> (32 - ks[25]); r ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[ 8] - r) & 0xffffffff; i = i << ks[24] | i >> (32 - ks[24]); l ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[ 7] ^ l) & 0xffffffff; i = i << ks[23] | i >> (32 - ks[23]); r ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[ 6] + r) & 0xffffffff; i = i << ks[22] | i >> (32 - ks[22]); l ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[ 5] - l) & 0xffffffff; i = i << ks[21] | i >> (32 - ks[21]); r ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[ 4] ^ r) & 0xffffffff; i = i << ks[20] | i >> (32 - ks[20]); l ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[ 3] + l) & 0xffffffff; i = i << ks[19] | i >> (32 - ks[19]); r ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    i = (ks[ 2] - r) & 0xffffffff; i = i << ks[18] | i >> (32 - ks[18]); l ^= ((s1[i >> 24 & 255] + s2[i >> 16 & 255]) ^ s3[i >> 8 & 255]) - s4[i & 255]
    i = (ks[ 1] ^ l) & 0xffffffff; i = i << ks[17] | i >> (32 - ks[17]); r ^= ((s1[i >> 24 & 255] - s2[i >> 16 & 255]) + s3[i >> 8 & 255]) ^ s4[i & 255]
    i = (ks[ 0] + r) & 0xffffffff; i = i << ks[16] | i >> (32 - ks[16]); l ^= ((s1[i >> 24 & 255] ^ s2[i >> 16 & 255]) - s3[i >> 8 & 255]) + s4[i & 255]
    return struct.pack('>LL', l & 0xffffffff, r & 0xffffffff)


# --- DES and DES3 (3DES) block ciphers.
#
# Based on: http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
# Based on: https://rosettacode.org/wiki/Data_Encryption_Standard#Python
#
# DES3 has the slowest pure Python implementation here, compared to other
# ciphers in the OpenPGP RFC.
#


def _des_permutation_by_table(block, block_len, table):
  result = 0
  for pos in table:
    result = result << 1 | (block >> (block_len - pos)) & 1
  return result


def _des_keysetup(key, _pbt=_des_permutation_by_table, _lrots=(lambda val: (val << 1) & 0xfffffff | val >> 27, lambda val: (val << 2) & 0xfffffff | val >> 26)):
  if not isinstance(key, (int, long)):
    raise TypeError
  if key >> 64:
    raise ValueError('DES key too large.')
  PC1 = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55,
         47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
  key = _pbt(key, 64, PC1) # 64bit -> PC1 -> 56bit.
  round_keys = [((key >> 28) & 0xfffffff, key & 0xfffffff)]
  for rot_val in (0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0):
    round_keys.append((_lrots[rot_val](round_keys[-1][0]), _lrots[rot_val](round_keys[-1][1])))
  del round_keys[0]
  PC2 = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30,
         40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)
  # 56bit -> PC2 -> 48bit.
  return tuple(_pbt((Ci << 28) | Di, 56, PC2) for Ci, Di in round_keys)  # tuple of 16 integers.


def _des_crypt(msg, round_keys, do_decrypt=False, _pbt=_des_permutation_by_table):
  #if not isinstance(msg, (int, long)):  # True, but we don't check for speed.
  #  raise TypeError
  #if msg >> 64:  # True, but we don't check for speed.
  #  raise ValueError('DES block too large.')
  IP = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16,
        8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)
  msg = _pbt(msg, 64, IP)
  L0, R0 = msg >> 32, msg & 0xffffffff
  if do_decrypt:
    round_keys = reversed(round_keys)
  E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22,
       23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)
  P = (16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25)
  RB = (0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23, 8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31,
        32, 48, 33, 49, 34, 50, 35, 51, 36, 52, 37, 53, 38, 54, 39, 55, 40, 56, 41, 57, 42, 58, 43, 59, 44, 60, 45, 61, 46, 62, 47, 63)
  for Ki in round_keys:
    Ri = Ki ^ _pbt(R0, 32, E)
    Ri = ((14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8,
           13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)[RB[(Ri >> 42) & 63]] << 28 |
          (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7,
           11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)[RB[(Ri >> 36) & 63]] << 24 |
          (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4,
           9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)[RB[(Ri >> 30) & 63]] << 20 |
          (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9,
           0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)[RB[(Ri >> 24) & 63]] << 16 |
          (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1,
           11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)[RB[(Ri >> 18) & 63]] << 12 |
          (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15,
           5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)[RB[(Ri >> 12) & 63]] << 8 |
          (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11,
           13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)[RB[(Ri >> 6) & 63]] << 4 |
          (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4,
           1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)[RB[Ri & 63]])
    L0, R0 = R0, L0 ^ _pbt(Ri, 32, P)
  IP_INV = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)
  return _pbt(R0 << 32 | L0, 64, IP_INV)


class DES(object):
  """DES block cipher."""

  key_size = 8
  block_size = 8

  __slots__ = ('_key')

  def __init__(self, key, _des_keysetup=_des_keysetup):
    if len(key) != 8:
      raise ValueError('DES key size must be 8, got: %d' % len(key))
    self._key = _des_keysetup(struct.unpack('>Q', key)[0])

  def encrypt(self, block, _pack=struct.pack, _unpack=struct.unpack, _des_crypt=_des_crypt):
    return _pack('>Q', _des_crypt(_unpack('>Q', block)[0], self._key))

  def decrypt(self, block, _pack=struct.pack, _unpack=struct.unpack, _des_crypt=_des_crypt):
    return _pack('>Q', _des_crypt(_unpack('>Q', block)[0], self._key, True))


class DES3(object):
  """DES3 (triple DES, 3des) block cipher."""

  key_size = 24  # Or 16.
  block_size = 8

  __slots__ = ('_key1', '_key2', '_key3')

  def __init__(self, key):
    if len(key) not in (16, 24):
      raise ValueError('DES3 key size must be 16 or 24, got: %d' % len(key))
    self._key1, self._key2 = DES(key[:8])._key, DES(key[8 : 16])._key
    if len(key) == 16:
      self._key3 = self._key1
    else:
      self._key3 = DES(key[16 : 24])._key

  def encrypt(self, block, _pack=struct.pack, _unpack=struct.unpack, _des_crypt=_des_crypt):
    return _pack('>Q', _des_crypt(_des_crypt(_des_crypt(_unpack('>Q', block)[0], self._key1), self._key2, 1), self._key3))

  def decrypt(self, block, _pack=struct.pack, _unpack=struct.unpack, _des_crypt=_des_crypt):
    return _pack('>Q', _des_crypt(_des_crypt(_des_crypt(_unpack('>Q', block)[0], self._key3, 1), self._key2), self._key1, 1))


del _des_permutation_by_table, _des_keysetup, _des_crypt


# --- Twofish block cipher.
#
# based on https://github.com/doegox/python-cryptoplus/blob/a5a1f8aecce4ddf476b2d80b586822d9e91eeb7d/src/CryptoPlus/Cipher/pytwofish.py
#
# Supports only little-endian operation (WORD_BIGENDIAN == 0), that's what GPG needs.
#
# Copyrights
# ==========
# pytwofish.py is by Bjorn Edstrom <be@bjrn.se> 13 december 2007.
#
# This code is a derived from an implementation by Dr Brian Gladman
# (gladman@seven77.demon.co.uk) which is subject to the following license.
# pytwofish.py is not subject to any other license.
#
#/* This is an independent implementation of the encryption algorithm:   */
#/*                                                                      */
#/*         Twofish by Bruce Schneier and colleagues                     */
#/*                                                                      */
#/* which is a candidate algorithm in the Advanced Encryption Standard   */
#/* programme of the US National Institute of Standards and Technology.  */
#/*                                                                      */
#/* Copyright in this implementation is held by Dr B R Gladman but I     */
#/* hereby give permission for its free direct or derivative use subject */
#/* to acknowledgment of its origin and compliance with any conditions   */
#/* that the originators of t he algorithm place on its exploitation.    */
#/*                                                                      */
#/* My thanks to Doug Whiting and Niels Ferguson for comments that led   */
#/* to improvements in this implementation.                              */
#/*                                                                      */
#/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */
#
# The above copyright notice must not be removed.


def _twofish_rotl1(x):
  return ((x << 1) & 0xffffffff) | (x >> 31)


def _twofish_rotr1(x):
  return (x >> 1) | ((x << 31) & 0xffffffff)


class Twofish(object):
  """Twofish block cipher."""

  block_size = 16
  key_size = 32

  __slots__ = ('_context',)

  def __init__(self, key):
    if len(key) not in (16, 24, 32):
      raise ValueError('Twofish key size must be 16, 24 or 32, got: %d' % len(key))
    in_key = struct.unpack('<%dL' % (len(key) >> 2), key)
    qtab0, qtab1 = [0] * 256, [0] * 256
    mtab = [[0] * 256, [0] * 256, [0] * 256, [0] * 256]
    klen = len(key) >> 3

    def rotr32(x, n):
      return (x >> n) | ((x << (32 - n)) & 0xffffffff)

    def rotl32(x, n):
      return ((x << n) & 0xffffffff) | (x >> (32 - n))

    def h_fun(x, mx_key):
      b0, b1, b2, b3 = x & 255, (x >> 8) & 255, (x >> 16) & 255, (x >> 24) & 255
      if klen >= 4:
        b0, b1, b2, b3 = qtab1[b0] ^ (mx_key[3] & 255), qtab0[b1] ^ ((mx_key[3] >> 8) & 255), qtab0[b2] ^ ((mx_key[3] >> 16) & 255), qtab1[b3] ^ ((mx_key[3] >> 24) & 255)
      if klen >= 3:
        b0, b1, b2, b3 = qtab1[b0] ^ (mx_key[2] & 255), qtab1[b1] ^ ((mx_key[2] >> 8) & 255), qtab0[b2] ^ ((mx_key[2] >> 16) & 255), qtab0[b3] ^ ((mx_key[2] >> 24) & 255)
      if klen >= 2:
        b0, b1 = qtab0[qtab0[b0] ^ (mx_key[1] & 255)] ^ (mx_key[0] & 255), qtab0[qtab1[b1] ^ ((mx_key[1] >> 8) & 255)] ^ ((mx_key[0] >> 8) & 255)
        b2, b3 = qtab1[qtab0[b2] ^ ((mx_key[1] >> 16) & 255)] ^ ((mx_key[0] >> 16) & 255), qtab1[qtab1[b3] ^ ((mx_key[1] >> 24) & 255)] ^ ((mx_key[0] >> 24) & 255)
      return mtab[0][b0] ^ mtab[1][b1] ^ mtab[2][b2] ^ mtab[3][b3]

    for i in xrange(256):
      a, b = (i >> 4) & 15, i & 15
      c, d = a, b = a ^ b, (0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)[b] ^ (0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7)[a]
      a, b = (8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4)[a], (14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13)[b]
      a, b = a ^ b, (0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)[b] ^ (0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7)[a]
      qtab0[i] = (11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1)[a] | (13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10)[b] << 4
      a, b = (2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5)[c], (1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8)[d]
      a, b = a ^ b, (0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)[b] ^ (0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7)[a]
      qtab1[i] = (4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15)[a] | (11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10)[b] << 4
    for i in xrange(256):
      f01 = qtab1[i]
      f5b, fef = ((f01) ^ ((f01) >> 2) ^ (0, 90, 180, 238)[(f01) & 3]), ((f01) ^ ((f01) >> 1) ^ ((f01) >> 2) ^ (0, 238, 180, 90)[(f01) & 3])
      mtab[0][i], mtab[2][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24), f5b + (fef << 8) + (f01 << 16) + (fef << 24)
      f01 = qtab0[i]
      f5b, fef = ((f01) ^ ((f01) >> 2) ^ (0, 90, 180, 238)[(f01) & 3]), ((f01) ^ ((f01) >> 1) ^ ((f01) >> 2) ^ (0, 238, 180, 90)[(f01) & 3])
      mtab[1][i], mtab[3][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24), f5b + (f01 << 8) + (fef << 16) + (f5b << 24)
    skey = [0] * klen
    for i in xrange(klen):
      a, b = in_key[i << 1], in_key[i << 1 | 1]
      for _ in xrange(8):
        t = b >> 24
        b = ((b << 8) & 0xffffffff) | (a >> 24)
        a, u = (a << 8) & 0xffffffff, (t << 1) & 0xffffffff
        if t & 0x80:
          u ^= 0x0000014d
        b ^= t ^ ((u << 16) & 0xffffffff)
        u ^= (t >> 1)
        if t & 0x01:
          u ^= 0x0000014d >> 1
        b ^= ((u << 24) & 0xffffffff) | ((u << 8) & 0xffffffff)
      skey[klen - i - 1] = b
    me_key, mo_key = tuple(in_key[i << 1] for i in xrange(klen)), tuple(in_key[i << 1 | 1] for i in xrange(klen))
    lkey = [0] * 40
    for i in xrange(0, 40, 2):
      a = (0x01010101 * i) & 0xffffffff
      b = (a + 0x01010101) & 0xffffffff
      a, b = h_fun(a, me_key), rotl32(h_fun(b, mo_key), 8)
      lkey[i] = (a + b) & 0xffffffff
      lkey[i + 1] = rotl32((a + (b << 1)) & 0xffffffff, 9)
    ntab = ([[0] * 256, [0] * 256, [0] * 256, [0] * 256])
    if klen == 2:
      for i in xrange(256):
        by = i & 0xff
        ntab[0][i] = mtab[0][qtab0[qtab0[by] ^ (skey[1] & 255)] ^ (skey[0] & 255)]
        ntab[1][i] = mtab[1][qtab0[qtab1[by] ^ ((skey[1] >> 8) & 255)] ^ ((skey[0] >> 8) & 255)]
        ntab[2][i] = mtab[2][qtab1[qtab0[by] ^ ((skey[1] >> 16) & 255)] ^ ((skey[0] >> 16) & 255)]
        ntab[3][i] = mtab[3][qtab1[qtab1[by] ^ ((skey[1] >> 24) & 255)] ^ ((skey[0] >> 24) & 255)]
    if klen == 3:
      for i in xrange(256):
        by = i & 0xff
        ntab[0][i] = mtab[0][qtab0[qtab0[qtab1[by] ^ (skey[2] & 255)] ^ (skey[1] & 255)] ^ (skey[0] & 255)]
        ntab[1][i] = mtab[1][qtab0[qtab1[qtab1[by] ^ ((skey[2] >> 8) & 255)] ^ ((skey[1] >> 8) & 255)] ^ ((skey[0] >> 8) & 255)]
        ntab[2][i] = mtab[2][qtab1[qtab0[qtab0[by] ^ ((skey[2] >> 16) & 255)] ^ ((skey[1] >> 16) & 255)] ^ ((skey[0] >> 16) & 255)]
        ntab[3][i] = mtab[3][qtab1[qtab1[qtab0[by] ^ ((skey[2] >> 24) & 255)] ^ ((skey[1] >> 24) & 255)] ^ ((skey[0] >> 24) & 255)]
    if klen == 4:
      for i in xrange(256):
        by = i & 0xff
        ntab[0][i] = mtab[0][qtab0[qtab0[qtab1[qtab1[by] ^ (skey[3] & 255)] ^ (skey[2] & 255)] ^ (skey[1] & 255)] ^ (skey[0] & 255)]
        ntab[1][i] = mtab[1][qtab0[qtab1[qtab1[qtab0[by] ^ ((skey[3] >> 8) & 255)] ^ ((skey[2] >> 8) & 255)] ^ ((skey[1] >> 8) & 255)] ^ ((skey[0] >> 8) & 255)]
        ntab[2][i] = mtab[2][qtab1[qtab0[qtab0[qtab0[by] ^ ((skey[3] >> 16) & 255)] ^ ((skey[2] >> 16) & 255)] ^ ((skey[1] >> 16) & 255)] ^ ((skey[0] >> 16) & 255)]
        ntab[3][i] = mtab[3][qtab1[qtab1[qtab0[qtab1[by] ^ ((skey[3] >> 24) & 255)] ^ ((skey[2] >> 24) & 255)] ^ ((skey[1] >> 24) & 255)] ^ ((skey[0] >> 24) & 255)]
    ntab = (tuple(ntab[0]), tuple(ntab[1]), tuple(ntab[2]), tuple(ntab[3]))
    self._context = (lkey, ntab)

  def encrypt(self, block, rotl1=_twofish_rotl1, rotr1=_twofish_rotr1):
    if len(block) != 16:
      raise ValueError('Twofish block size must be 16, got: %d' % len(block))
    A, B, C, D = struct.unpack('<4L', block)
    lkey, ntab = self._context
    a, b, c, d = A ^ lkey[0], B ^ lkey[1], C ^ lkey[2], D ^ lkey[3]
    for i in xrange(8):
      t1 = (ntab[0][((b >> 24) & 255)] ^ ntab[1][(b & 255)] ^ ntab[2][((b >> 8) & 255)] ^ ntab[3][((b >> 16) & 255)])
      t0 = (ntab[0][(a & 255)] ^ ntab[1][((a >> 8) & 255)] ^ ntab[2][((a >> 16) & 255)] ^ ntab[3][((a >> 24) & 255)])
      c = rotr1(c ^ ((t0 + t1 + lkey[4 * (i) + 8]) & 0xffffffff))
      d = rotl1(d) ^ ((t0 + 2 * t1 + lkey[4 * (i) + 9]) & 0xffffffff)
      t1 = (ntab[0][((d >> 24) & 255)] ^ ntab[1][(d & 255)] ^ ntab[2][((d >> 8) & 255)] ^ ntab[3][((d >> 16) & 255)])
      t0 = (ntab[0][(c & 255)] ^ ntab[1][((c >> 8) & 255)] ^ ntab[2][((c >> 16) & 255)] ^ ntab[3][((c >> 24) & 255)])
      a = rotr1(a ^ ((t0 + t1 + lkey[4 * (i) + 10]) & 0xffffffff))
      b = rotl1(b) ^ ((t0 + 2 * t1 + lkey[4 * (i) + 11]) & 0xffffffff)
    return struct.pack('<4L', c ^ lkey[4], d ^ lkey[5], a ^ lkey[6], b ^ lkey[7])

  def decrypt(self, block, rotl1=_twofish_rotl1, rotr1=_twofish_rotr1):
    if len(block) != 16:
      raise ValueError('Twofish block size must be 16, got: %d' % len(block))
    A, B, C, D = struct.unpack('<4L', block)
    lkey, ntab = self._context
    a, b, c, d = A ^ lkey[4], B ^ lkey[5], C ^ lkey[6], D ^ lkey[7]
    for i in xrange(7, -1, -1):
      t1 = (ntab[0][((b >> 24) & 255)] ^ ntab[1][(b & 255)] ^ ntab[2][((b >> 8) & 255)] ^ ntab[3][((b >> 16) & 255)])
      t0 = (ntab[0][(a & 255)] ^ ntab[1][((a >> 8) & 255)] ^ ntab[2][((a >> 16) & 255)] ^ ntab[3][((a >> 24) & 255)])
      c = rotl1(c) ^ ((t0 + t1 + lkey[4 * (i) + 10]) & 0xffffffff)
      d = rotr1(d ^ ((t0 + 2 * t1 + lkey[4 * (i) + 11]) & 0xffffffff))
      t1 = (ntab[0][((d >> 24) & 255)] ^ ntab[1][(d & 255)] ^ ntab[2][((d >> 8) & 255)] ^ ntab[3][((d >> 16) & 255)])
      t0 = (ntab[0][(c & 255)] ^ ntab[1][((c >> 8) & 255)] ^ ntab[2][((c >> 16) & 255)] ^ ntab[3][((c >> 24) & 255)])
      a = rotl1(a) ^ ((t0 + t1 + lkey[4 * (i) + 8]) & 0xffffffff)
      b = rotr1(b ^ ((t0 + 2 * t1 + lkey[4 * (i) + 9]) & 0xffffffff))
    return struct.pack('<4L', c ^ lkey[0], d ^ lkey[1], a ^ lkey[2], b ^ lkey[3])


del _twofish_rotl1, _twofish_rotr1


# --- IDEA block cipher.


def _idea_mul(a, b):
  if a:
    if b:
      p = a * b
      b, a = p & 0xffff, p >> 16
      return (b - a + (b < a)) & 0xffff
    else:
      return (1 - a) & 0xffff
  else:
    return (1 - b) & 0xffff


def _idea_inv(x):
  if x <= 1:
    return x
  t1, y = divmod(0x10001, x)
  t0 = 1
  while y != 1:  # Eucledian GCD.
    q, x = divmod(x, y)
    t0 += q * t1
    if x == 1:
      return t0
    q, y = divmod(y, x)
    t1 += q * t0
  return (1 - t1) & 0xffff


def _idea_crypt(ckey, block, _mul=_idea_mul, _pack=struct.pack, _unpack=struct.unpack):
  if len(block) != 8:
    raise ValueError('IDEA block size must be 8, got: %d' % len(block))
  a, b, c, d = _unpack('>4H', block)
  for j in xrange(0, 48, 6):
    a, b, c, d = _mul(a, ckey[j]), (b + ckey[j + 1]) & 0xffff, (c + ckey[j + 2]) & 0xffff, _mul(d, ckey[j + 3])
    t, u = c, b
    c = _mul(a ^ c, ckey[j + 4])
    b = _mul(((b ^ d) + c) & 0xffff, ckey[j + 5])
    c = (c + b) & 0xffff
    a ^= b
    d ^= c
    b ^= t
    c ^= u
  return _pack('>4H', _mul(a, ckey[48]), (c + ckey[49]) & 0xffff, (b + ckey[50]) & 0xffff, _mul(d, ckey[51]))


class IDEA(object):
  """IDEA block cipher."""

  key_size = 16
  block_size = 8

  __slots__ = ('_ckey', '_dkey')

  def __init__(self, key, _inv=_idea_inv):
    if len(key) != 16:
      raise ValueError('IDEA key size must be 16, got: %d' % len(key))
    ckey = [0] * 52
    ckey[:8] = struct.unpack('>8H', key)
    for i in xrange(0, 44):
      ckey[i + 8] = (ckey[(i & ~7) + ((i + 1) & 7)] << 9 | ckey[(i & ~7) + ((i + 2) & 7)] >> 7) & 0xffff
    self._ckey = tuple(ckey)
    dkey = [0] * 52
    dkey[48], dkey[49], dkey[50], dkey[51] = _inv(ckey[0]), 0xffff & -ckey[1], 0xffff & -ckey[2], _inv(ckey[3])
    for i in xrange(42, -6, -6):
      dkey[i + 4], dkey[i + 5], dkey[i], dkey[i + 3] = ckey[46 - i], ckey[47 - i], _inv(ckey[48 - i]), _inv(ckey[51 - i])
      dkey[i + 1 + (i > 0)], dkey[i + 2 - (i > 0)] = 0xffff & -ckey[49 - i], 0xffff & -ckey[50 - i]
    self._dkey = tuple(dkey)

  def encrypt(self, block, _idea_crypt=_idea_crypt):
    return _idea_crypt(self._ckey, block)

  def decrypt(self, block, _idea_crypt=_idea_crypt):
    return _idea_crypt(self._dkey, block)


del _idea_mul, _idea_inv, _idea_crypt


