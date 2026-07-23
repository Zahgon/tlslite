

from .utils import cryptomath
from .utils.tackwrapper import *
from .utils.pem import *
from .x509 import X509

class X509CertChain(object):

    def __init__(self, x509List=None):
        """Create a new X509CertChain.

        @type x509List: list
        @param x509List: A list of L{tlslite.x509.X509} instances,
        starting with the end-entity certificate and with every
        subsequent certificate certifying the previous.
        """
        if x509List:
            self.x509List = x509List
        else:
            self.x509List = []

    def parsePemList(self, s):
        pass

    def getNumCerts(self):
        pass

    def getEndEntityPublicKey(self):
        pass

    def getFingerprint(self):
        pass
        
    def checkTack(self, tack):
        pass
        
    def getTackExt(self):
        pass
                
