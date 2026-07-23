
try:
    from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
except ImportError:
    from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from .tlssocketservermixin import TLSSocketServerMixIn


class TLSXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    
    def setup(self):
        pass
        
    def do_POST(self):
        pass


class TLSXMLRPCServer(TLSSocketServerMixIn,
                      SimpleXMLRPCServer):

    def __init__(self, addr, *args, **kwargs):
        if not args and not 'requestHandler' in kwargs:
            kwargs['requestHandler'] = TLSXMLRPCRequestHandler
        SimpleXMLRPCServer.__init__(self, addr, *args, **kwargs)


class MultiPathTLSXMLRPCServer(TLSXMLRPCServer):

    def __init__(self, addr, *args, **kwargs):
        TLSXMLRPCServer.__init__(addr, *args, **kwargs)
        self.dispatchers = {}
        self.allow_none = allow_none
        self.encoding = encoding
