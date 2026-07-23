
from .compat import *
from .codec import *

class ASN1Parser(object):
    def __init__(self, bytes):
        p = Parser(bytes)
        p.get(1) #skip Type

        self.length = self._getASN1Length(p)

        self.value = p.getFixBytes(self.length)

    def getChild(self, which):
        return ASN1Parser(self.getChildBytes(which))

    def getChildBytes(self, which):
        p = Parser(self.value)
        for x in range(which+1):
            markIndex = p.index
            p.get(1) #skip Type
            length = self._getASN1Length(p)
            p.getFixBytes(length)
        return p.bytes[markIndex : p.index]

    def _getASN1Length(self, p):
        firstLength = p.get(1)
        if firstLength<=127:
            return firstLength
        else:
            lengthLength = firstLength & 0x7F
            return p.get(lengthLength)
