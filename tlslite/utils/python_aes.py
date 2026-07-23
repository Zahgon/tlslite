

from .cryptomath import *

from .aes import *
from .rijndael import rijndael

def new(key, mode, IV):
    pass

class Python_AES(AES):
    def __init__(self, key, mode, IV):
        AES.__init__(self, key, mode, IV, "python")
        self.rijndael = rijndael(key, 16)
        self.IV = IV

    def encrypt(self, plaintext):
        AES.encrypt(self, plaintext)

        plaintextBytes = plaintext[:]
        chainBytes = self.IV[:]

        for x in range(len(plaintextBytes)//16):

            blockBytes = plaintextBytes[x*16 : (x*16)+16]
            for y in range(16):
                blockBytes[y] ^= chainBytes[y]

            encryptedBytes = self.rijndael.encrypt(blockBytes)

            for y in range(16):
                plaintextBytes[(x*16)+y] = encryptedBytes[y]

            chainBytes = encryptedBytes

        self.IV = chainBytes[:]
        return plaintextBytes

    def decrypt(self, ciphertext):
        AES.decrypt(self, ciphertext)

        ciphertextBytes = ciphertext[:]
        chainBytes = self.IV[:]

        for x in range(len(ciphertextBytes)//16):

            blockBytes = ciphertextBytes[x*16 : (x*16)+16]
            decryptedBytes = self.rijndael.decrypt(blockBytes)

            for y in range(16):
                decryptedBytes[y] ^= chainBytes[y]
                ciphertextBytes[(x*16)+y] = decryptedBytes[y]

            chainBytes = blockBytes

        self.IV = chainBytes[:]
        return ciphertextBytes
