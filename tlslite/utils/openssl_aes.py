

from .cryptomath import *
from .aes import *

if m2cryptoLoaded:

    def new(key, mode, IV):
        pass

    class OpenSSL_AES(AES):

        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, "openssl")
            self.key = key
            self.IV = IV

        def _createContext(self, encrypt):
            context = m2.cipher_ctx_new()
            if len(self.key)==16:
                cipherType = m2.aes_128_cbc()
            if len(self.key)==24:
                cipherType = m2.aes_192_cbc()
            if len(self.key)==32:
                cipherType = m2.aes_256_cbc()
            m2.cipher_init(context, cipherType, self.key, self.IV, encrypt)
            return context

        def encrypt(self, plaintext):
            AES.encrypt(self, plaintext)
            context = self._createContext(1)
            ciphertext = m2.cipher_update(context, plaintext)
            m2.cipher_ctx_free(context)
            self.IV = ciphertext[-self.block_size:]
            return bytearray(ciphertext)

        def decrypt(self, ciphertext):
            AES.decrypt(self, ciphertext)
            context = self._createContext(0)
            plaintext = m2.cipher_update(context, ciphertext+('\0'*16))

            plaintext = plaintext[:len(ciphertext)]
            m2.cipher_ctx_free(context)
            self.IV = ciphertext[-self.block_size:]
            return bytearray(plaintext)
