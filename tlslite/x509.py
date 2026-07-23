

from .utils.asn1parser import ASN1Parser
from .utils.cryptomath import *
from .utils.keyfactory import _createPublicRSAKey
from .utils.pem import *


class X509(object):

    def __init__(self):
        self.bytes = bytearray(0)
        self.publicKey = None
        self.subject = None

    def parse(self, s):
        """Parse a PEM-encoded X.509 certificate.

        @type s: str
        @param s: A PEM-encoded X.509 certificate (i.e. a base64-encoded
        certificate wrapped with "-----BEGIN CERTIFICATE-----" and
        "-----END CERTIFICATE-----" tags).
        """

        bytes = dePem(s, "CERTIFICATE")
        self.parseBinary(bytes)
        return self

    def parseBinary(self, bytes):
        """Parse a DER-encoded X.509 certificate.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: A DER-encoded X.509 certificate.
        """

        self.bytes = bytearray(bytes)
        p = ASN1Parser(bytes)

        tbsCertificateP = p.getChild(0)

        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
        else:
            subjectPublicKeyInfoIndex = 5

        self.subject = tbsCertificateP.getChildBytes(\
                           subjectPublicKeyInfoIndex - 1)

        subjectPublicKeyInfoP = tbsCertificateP.getChild(\
                                    subjectPublicKeyInfoIndex)

        algorithmP = subjectPublicKeyInfoP.getChild(0)
        rsaOID = algorithmP.value
        if list(rsaOID) != [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0]:
            raise SyntaxError("Unrecognized AlgorithmIdentifier")

        subjectPublicKeyP = subjectPublicKeyInfoP.getChild(1)

        if (subjectPublicKeyP.value[0] !=0):
            raise SyntaxError()
        subjectPublicKeyP = ASN1Parser(subjectPublicKeyP.value[1:])

        modulusP = subjectPublicKeyP.getChild(0)
        publicExponentP = subjectPublicKeyP.getChild(1)

        n = bytesToNumber(modulusP.value)
        e = bytesToNumber(publicExponentP.value)

        self.publicKey = _createPublicRSAKey(n, e)

    def getFingerprint(self):
        pass

    def writeBytes(self):
        return self.bytes


