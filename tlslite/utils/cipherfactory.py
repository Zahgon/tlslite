

import os

from tlslite.utils import python_aes
from tlslite.utils import python_rc4

from tlslite.utils import cryptomath

tripleDESPresent = False

if cryptomath.m2cryptoLoaded:
    from tlslite.utils import openssl_aes
    from tlslite.utils import openssl_rc4
    from tlslite.utils import openssl_tripledes
    tripleDESPresent = True

if cryptomath.pycryptoLoaded:
    from tlslite.utils import pycrypto_aes
    from tlslite.utils import pycrypto_rc4
    from tlslite.utils import pycrypto_tripledes
    tripleDESPresent = True


def createAES(key, IV, implList=None):
    pass

def createRC4(key, IV, implList=None):
    pass

def createTripleDES(key, IV, implList=None):
    pass
