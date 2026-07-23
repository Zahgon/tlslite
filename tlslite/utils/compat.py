

import sys
import os
import math
import binascii

if sys.version_info >= (3,0):

    def compat26Str(x): return x
    
    
    def compatHMAC(x): return bytes(x)
    
    def raw_input(s):
        pass
    
    def a2b_hex(s):
        pass

    def a2b_base64(s):
        try:
            b = bytearray(binascii.a2b_base64(bytearray(s, "ascii")))
        except Exception as e:
            raise SyntaxError("base64 error: %s" % e)
        return b

    def b2a_hex(b):
        pass
            
    def b2a_base64(b):
        pass

    def readStdinBinary():
        pass

    def compatLong(num):
        return int(num)

else:
    if sys.version_info < (2,7):
        def compat26Str(x): return str(x)
    else:
        def compat26Str(x): return x

    def compatHMAC(x): return compat26Str(x)

    def a2b_hex(s):
        pass

    def a2b_base64(s):
        try:
            b = bytearray(binascii.a2b_base64(s))
        except Exception as e:
            raise SyntaxError("base64 error: %s" % e)
        return b
        
    def b2a_hex(b):
        pass
        
    def b2a_base64(b):
        pass

    def compatLong(num):
        return long(num)
        
import traceback
def formatExceptionTrace(e):
    newStr = "".join(traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback))
    return newStr

