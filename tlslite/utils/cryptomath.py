
from __future__ import print_function
import os
import math
import base64
import binascii

from .compat import *



try:
    from M2Crypto import m2
    m2cryptoLoaded = True

except ImportError:
    m2cryptoLoaded = False

try:
    import gmpy
    gmpyLoaded = True
except ImportError:
    gmpyLoaded = False

try:
    import Crypto.Cipher.AES
    pycryptoLoaded = True
except ImportError:
    pycryptoLoaded = False



import zlib
length = len(zlib.compress(os.urandom(1000)))
assert(length > 900)
del length

def getRandomBytes(howMany):
    b = bytearray(os.urandom(howMany))
    assert(len(b) == howMany)
    return b

prngName = "os.urandom"


import hmac
import hashlib

def MD5(b):
    pass

def SHA1(b):
    pass

def HMAC_MD5(k, b):
    pass

def HMAC_SHA1(k, b):
    pass

def HMAC_SHA256(k, b):
    pass


def bytesToNumber(b):
    total = 0
    multiplier = 1
    for count in range(len(b)-1, -1, -1):
        byte = b[count]
        total += multiplier * byte
        multiplier *= 256
    return total

def numberToByteArray(n, howManyBytes=None):
    """Convert an integer into a bytearray, zero-pad to howManyBytes.

    The returned bytearray may be smaller than howManyBytes, but will
    not be larger.  The returned bytearray will contain a big-endian
    encoding of the input integer (n).
    """    
    if howManyBytes == None:
        howManyBytes = numBytes(n)
    b = bytearray(howManyBytes)
    for count in range(howManyBytes-1, -1, -1):
        b[count] = int(n % 256)
        n >>= 8
    return b

def mpiToNumber(mpi): #mpi is an openssl-format bignum string
    pass

def numberToMPI(n):
    pass



def numBits(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    return int(math.floor(math.log(n, 2))+1)

def numBytes(n):
    if n==0:
        return 0
    bits = numBits(n)
    return int(math.ceil(bits / 8.0))


def getRandomNumber(low, high):
    if low >= high:
        raise AssertionError()
    howManyBits = numBits(high)
    howManyBytes = numBytes(high)
    lastBits = howManyBits % 8
    while 1:
        bytes = getRandomBytes(howManyBytes)
        if lastBits:
            bytes[0] = bytes[0] % (1 << lastBits)
        n = bytesToNumber(bytes)
        if n >= low and n < high:
            return n

def gcd(a,b):
    pass

def lcm(a, b):
    pass

def invMod(a, b):
    c, d = a, b
    uc, ud = 1, 0
    while c != 0:
        q = d // c
        c, d = d-(q*c), c
        uc, ud = ud - (q * uc), uc
    if d == 1:
        return ud % b
    return 0


if gmpyLoaded:
    def powMod(base, power, modulus):
        base = gmpy.mpz(base)
        power = gmpy.mpz(power)
        modulus = gmpy.mpz(modulus)
        result = pow(base, power, modulus)
        return compatLong(result)

else:
    def powMod(base, power, modulus):
        if power < 0:
            result = pow(base, power*-1, modulus)
            result = invMod(result, modulus)
            return result
        else:
            return pow(base, power, modulus)

def makeSieve(n):
    sieve = list(range(n))
    for count in range(2, int(math.sqrt(n))+1):
        if sieve[count] == 0:
            continue
        x = sieve[count] * 2
        while x < len(sieve):
            sieve[x] = 0
            x += sieve[count]
    sieve = [x for x in sieve[2:] if x]
    return sieve

def isPrime(n, iterations=5, display=False, sieve=makeSieve(1000)):
    for x in sieve:
        if x >= n: return True
        if n % x == 0: return False
    if display: print("*", end=' ')
    s, t = n-1, 0
    while s % 2 == 0:
        s, t = s//2, t+1
    a = 2 #Use 2 as a base for first iteration speedup, per HAC
    for count in range(iterations):
        v = powMod(a, s, n)
        if v==1:
            continue
        i = 0
        while v != n-1:
            if i == t-1:
                return False
            else:
                v, i = powMod(v, 2, n), i+1
        a = getRandomNumber(2, n)
    return True

def getRandomPrime(bits, display=False):
    pass

def getRandomSafePrime(bits, display=False):
    pass
