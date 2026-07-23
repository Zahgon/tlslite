


import asyncore
from tlslite.tlsconnection import TLSConnection
from .asyncstatemachine import AsyncStateMachine


class TLSAsyncDispatcherMixIn(AsyncStateMachine):


    def __init__(self, sock=None):
        AsyncStateMachine.__init__(self)

        if sock:
            self.tlsConnection = TLSConnection(sock)

        for cl in self.__class__.__bases__:
            if cl != TLSAsyncDispatcherMixIn and cl != AsyncStateMachine:
                self.siblingClass = cl
                break
        else:
            raise AssertionError()

    def readable(self):
        pass

    def writable(self):
        pass

    def handle_read(self):
        pass

    def handle_write(self):
        pass

    def outConnectEvent(self):
        pass

    def outCloseEvent(self):
        asyncore.dispatcher.close(self)

    def outReadEvent(self, readBuffer):
        pass

    def outWriteEvent(self):
        pass

    def recv(self, bufferSize=16384):
        if bufferSize < 16384 or self.readBuffer == None:
            raise AssertionError()
        returnValue = self.readBuffer
        self.readBuffer = None
        return returnValue

    def send(self, writeBuffer):
        self.setWriteOp(writeBuffer)
        return len(writeBuffer)

    def close(self):
        if hasattr(self, "tlsConnection"):
            self.setCloseOp()
        else:
            asyncore.dispatcher.close(self)
