

from .cryptomath import *

from .rsakey import *
from .python_rsakey import Python_RSAKey
from .compat import compatLong

if pycryptoLoaded:

    from Crypto.PublicKey import RSA

    class PyCrypto_RSAKey(RSAKey):
        def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0):
            if not d:
                self.rsa = RSA.construct((compatLong(n), compatLong(e)))
            else:
                self.rsa = RSA.construct((compatLong(n), compatLong(e),
                                          compatLong(d), compatLong(p),
                                          compatLong(q)))

        def __getattr__(self, name):
            return getattr(self.rsa, name)

        def hasPrivateKey(self):
            return self.rsa.has_private()

        def _rawPrivateKeyOp(self, m):
            c = self.rsa.decrypt((m,))
            return c

        def _rawPublicKeyOp(self, c):
            m = self.rsa.encrypt(c, None)[0]
            return m

        def generate(bits):
            pass
        generate = staticmethod(generate)
