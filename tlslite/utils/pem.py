
from .compat import *
import binascii


def dePem(s, name):
    """Decode a PEM string into a bytearray of its payload.
    
    The input must contain an appropriate PEM prefix and postfix
    based on the input name string, e.g. for name="CERTIFICATE"::

      -----BEGIN CERTIFICATE-----
      MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
      ...
      KoZIhvcNAQEFBQADAwA5kw==
      -----END CERTIFICATE-----

    The first such PEM block in the input will be found, and its
    payload will be base64 decoded and returned.
    """
    prefix  = "-----BEGIN %s-----" % name
    postfix = "-----END %s-----" % name    
    start = s.find(prefix)
    if start == -1:
        raise SyntaxError("Missing PEM prefix")
    end = s.find(postfix, start+len(prefix))
    if end == -1:
        raise SyntaxError("Missing PEM postfix")
    s = s[start+len("-----BEGIN %s-----" % name) : end]
    retBytes = a2b_base64(s) # May raise SyntaxError
    return retBytes
    
def dePemList(s, name):
    pass

def pem(b, name):
    pass

def pemSniff(inStr, name):
    searchStr = "-----BEGIN %s-----" % name
    return searchStr in inStr
