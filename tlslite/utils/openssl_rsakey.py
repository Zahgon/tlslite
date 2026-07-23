

from .cryptomath import *

from .rsakey import *
from .python_rsakey import Python_RSAKey

def password_callback(v, prompt1='Enter private key passphrase:',
                           prompt2='Verify passphrase:'):
    pass


if m2cryptoLoaded:
    class OpenSSL_RSAKey(RSAKey):
        def __init__(self, n=0, e=0):
            self.rsa = None
            self._hasPrivateKey = False
            if (n and not e) or (e and not n):
                raise AssertionError()
            if n and e:
                self.rsa = m2.rsa_new()
                m2.rsa_set_n(self.rsa, numberToMPI(n))
                m2.rsa_set_e(self.rsa, numberToMPI(e))

        def __del__(self):
            if self.rsa:
                m2.rsa_free(self.rsa)

        def __getattr__(self, name):
            if name == 'e':
                if not self.rsa:
                    return 0
                return mpiToNumber(m2.rsa_get_e(self.rsa))
            elif name == 'n':
                if not self.rsa:
                    return 0
                return mpiToNumber(m2.rsa_get_n(self.rsa))
            else:
                raise AttributeError

        def hasPrivateKey(self):
            return self._hasPrivateKey

        def _rawPrivateKeyOp(self, m):
            b = numberToByteArray(m, numBytes(self.n))
            s = m2.rsa_private_encrypt(self.rsa, bytes(b), m2.no_padding)
            c = bytesToNumber(bytearray(s))
            return c

        def _rawPublicKeyOp(self, c):
            b = numberToByteArray(c, numBytes(self.n))
            s = m2.rsa_public_decrypt(self.rsa, bytes(b), m2.no_padding)
            m = bytesToNumber(bytearray(s))
            return m

        pass

        def write(self, password=None):
            bio = m2.bio_new(m2.bio_s_mem())
            if self._hasPrivateKey:
                if password:
                    pass
                    m2.rsa_write_key(self.rsa, bio, m2.des_ede_cbc(), f)
                else:
                    def f(): pass
                    m2.rsa_write_key_no_cipher(self.rsa, bio, f)
            else:
                if password:
                    raise AssertionError()
                m2.rsa_write_pub_key(self.rsa, bio)
            s = m2.bio_read(bio, m2.bio_ctrl_pending(bio))
            m2.bio_free(bio)
            return s

        def generate(bits):
            pass
        generate = staticmethod(generate)

        def parse(s, passwordCallback=None):
            start = s.find("-----BEGIN ")
            if start == -1:
                raise SyntaxError()
            s = s[start:]            
            if s.startswith("-----BEGIN "):
                if passwordCallback==None:
                    callback = password_callback
                else:
                    def f(v, prompt1=None, prompt2=None):
                        pass
                    callback = f
                bio = m2.bio_new(m2.bio_s_mem())
                try:
                    m2.bio_write(bio, s)
                    key = OpenSSL_RSAKey()
                    if s.startswith("-----BEGIN RSA PRIVATE KEY-----"):
                        def f():pass
                        key.rsa = m2.rsa_read_key(bio, callback)
                        if key.rsa == None:
                            raise SyntaxError()
                        key._hasPrivateKey = True
                    elif s.startswith("-----BEGIN PRIVATE KEY-----"):
                        def f():pass
                        key.rsa = m2.pkey_read_pem(bio, callback)
                        if key.rsa == None:
                            raise SyntaxError()
                        key.rsa = m2.pkey_get1_rsa(key.rsa)
                        if key.rsa == None:
                            raise SyntaxError()
                        key._hasPrivateKey = True
                    elif s.startswith("-----BEGIN PUBLIC KEY-----"):
                        key.rsa = m2.rsa_read_pub_key(bio)
                        if key.rsa == None:
                            raise SyntaxError()
                        key._hasPrivateKey = False
                    else:
                        raise SyntaxError()
                    return key
                finally:
                    m2.bio_free(bio)
            else:
                raise SyntaxError()

        parse = staticmethod(parse)
