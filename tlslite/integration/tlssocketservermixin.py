

from tlslite.tlsconnection import TLSConnection

class TLSSocketServerMixIn:


    def finish_request(self, sock, client_address):
        pass

    def handshake(self, tlsConnection):
        raise NotImplementedError()