

from .utils.compat import *
from .mathtls import *
from .constants import *

class Session(object):

    def __init__(self):
        self.masterSecret = bytearray(0)
        self.sessionID = bytearray(0)
        self.cipherSuite = 0
        self.srpUsername = ""
        self.clientCertChain = None
        self.serverCertChain = None
        self.tackExt = None
        self.tackInHelloExt = False
        self.serverName = ""
        self.resumable = False

    def create(self, masterSecret, sessionID, cipherSuite,
            srpUsername, clientCertChain, serverCertChain, 
            tackExt, tackInHelloExt, serverName, resumable=True):
        self.masterSecret = masterSecret
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
        self.srpUsername = srpUsername
        self.clientCertChain = clientCertChain
        self.serverCertChain = serverCertChain
        self.tackExt = tackExt
        self.tackInHelloExt = tackInHelloExt  
        self.serverName = serverName
        self.resumable = resumable

    def _clone(self):
        pass

    def valid(self):
        pass

    def _setResumable(self, boolean):
        pass

    def getTackId(self):
        pass
        
    def getBreakSigs(self):
        pass

    def getCipherName(self):
        pass
        
    def getMacName(self):
        pass
