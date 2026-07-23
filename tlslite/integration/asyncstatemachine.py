

class AsyncStateMachine:

    def __init__(self):
        self._clear()

    def _clear(self):
        self.handshaker = None
        self.closer = None
        self.reader = None
        self.writer = None

        self.result = None

    def _checkAssert(self, maxActive=1):
        activeOps = 0
        if self.handshaker:
            activeOps += 1
        if self.closer:
            activeOps += 1
        if self.reader:
            activeOps += 1
        if self.writer:
            activeOps += 1

        if self.result == None:
            if activeOps != 0:
                raise AssertionError()
        elif self.result in (0,1):
            if activeOps != 1:
                raise AssertionError()
        else:
            raise AssertionError()
        if activeOps > maxActive:
            raise AssertionError()

    def wantsReadEvent(self):
        pass

    def wantsWriteEvent(self):
        pass

    def outConnectEvent(self):
        """Called when a handshake operation completes.

        May be overridden in subclass.
        """
        pass

    def outCloseEvent(self):
        """Called when a close operation completes.

        May be overridden in subclass.
        """
        pass

    def outReadEvent(self, readBuffer):
        """Called when a read operation completes.

        May be overridden in subclass."""
        pass

    def outWriteEvent(self):
        """Called when a write operation completes.

        May be overridden in subclass."""
        pass

    def inReadEvent(self):
        pass

    def inWriteEvent(self):
        pass

    def _doHandshakeOp(self):
        pass

    def _doCloseOp(self):
        try:
            self.result = self.closer.next()
        except StopIteration:
            self.closer = None
            self.result = None
            self.outCloseEvent()

    def _doReadOp(self):
        pass

    def _doWriteOp(self):
        try:
            self.result = self.writer.next()
        except StopIteration:
            self.writer = None
            self.result = None

    def setHandshakeOp(self, handshaker):
        pass

    def setServerHandshakeOp(self, **args):
        pass

    def setCloseOp(self):
        """Start a close operation.
        """
        try:
            self._checkAssert(0)
            self.closer = self.tlsConnection.closeAsync()
            self._doCloseOp()
        except:
            self._clear()
            raise

    def setWriteOp(self, writeBuffer):
        """Start a write operation.

        @type writeBuffer: str
        @param writeBuffer: The string to transmit.
        """
        try:
            self._checkAssert(0)
            self.writer = self.tlsConnection.writeAsync(writeBuffer)
            self._doWriteOp()
        except:
            self._clear()
            raise

