

from .cryptomath import *
from .tripledes import *

if pycryptoLoaded:
    import Crypto.Cipher.DES3

    def new(key, mode, IV):
        pass

    class PyCrypto_TripleDES(TripleDES):

        def __init__(self, key, mode, IV):
            TripleDES.__init__(self, key, mode, IV, "pycrypto")
            key = bytes(key)
            IV = bytes(IV)
            self.context = Crypto.Cipher.DES3.new(key, mode, IV)

        def encrypt(self, plaintext):
            plaintext = bytes(plaintext)
            return bytearray(self.context.encrypt(plaintext))

        def decrypt(self, ciphertext):
            ciphertext = bytes(ciphertext)
            return bytearray(self.context.decrypt(ciphertext))