

from .cryptomath import *
from .tripledes import *

if m2cryptoLoaded:

    def new(key, mode, IV):
        pass

    class OpenSSL_TripleDES(TripleDES):

        def __init__(self, key, mode, IV):
            TripleDES.__init__(self, key, mode, IV, "openssl")
            self.key = key
            self.IV = IV

        def _createContext(self, encrypt):
            context = m2.cipher_ctx_new()
            cipherType = m2.des_ede3_cbc()
            m2.cipher_init(context, cipherType, self.key, self.IV, encrypt)
            return context

        def encrypt(self, plaintext):
            TripleDES.encrypt(self, plaintext)
            context = self._createContext(1)
            ciphertext = m2.cipher_update(context, plaintext)
            m2.cipher_ctx_free(context)
            self.IV = ciphertext[-self.block_size:]
            return bytearray(ciphertext)

        def decrypt(self, ciphertext):
            TripleDES.decrypt(self, ciphertext)
            context = self._createContext(0)
            plaintext = m2.cipher_update(context, ciphertext+('\0'*16))

            plaintext = plaintext[:len(ciphertext)]
            m2.cipher_ctx_free(context)
            self.IV = ciphertext[-self.block_size:]
            return bytearray(plaintext)