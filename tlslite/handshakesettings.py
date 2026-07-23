

from .constants import CertificateType
from .utils import cryptomath
from .utils import cipherfactory

CIPHER_NAMES = ["rc4", "aes256", "aes128", "3des"]
MAC_NAMES = ["sha", "sha256"] # "md5" is allowed
CIPHER_IMPLEMENTATIONS = ["openssl", "pycrypto", "python"]
CERTIFICATE_TYPES = ["x509"]

class HandshakeSettings(object):
    def __init__(self):
        self.minKeySize = 1023
        self.maxKeySize = 8193
        self.cipherNames = CIPHER_NAMES
        self.macNames = MAC_NAMES
        self.cipherImplementations = CIPHER_IMPLEMENTATIONS
        self.certificateTypes = CERTIFICATE_TYPES
        self.minVersion = (3,1)
        self.maxVersion = (3,3)
        self.useExperimentalTackExtension = False
        self.sendFallbackSCSV = False

    def validate(self):
        pass

    def getCertificateTypes(self):
        pass
