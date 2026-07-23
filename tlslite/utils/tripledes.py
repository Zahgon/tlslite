

class TripleDES(object):
    def __init__(self, key, mode, IV, implementation):
        if len(key) != 24:
            raise ValueError()
        if mode != 2:
            raise ValueError()
        if len(IV) != 8:
            raise ValueError()
        self.isBlockCipher = True
        self.block_size = 8
        self.implementation = implementation
        self.name = "3des"

    def encrypt(self, plaintext):
        assert(len(plaintext) % 8 == 0)

    def decrypt(self, ciphertext):
        assert(len(ciphertext) % 8 == 0)
