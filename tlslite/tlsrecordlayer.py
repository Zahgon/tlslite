
from __future__ import generators

from .utils.compat import *
from .utils.cryptomath import *
from .utils.cipherfactory import createAES, createRC4, createTripleDES
from .utils.codec import *
from .errors import *
from .messages import *
from .mathtls import *
from .constants import *
from .utils.cryptomath import getRandomBytes

import socket
import errno
import traceback

class _ConnectionState(object):
    def __init__(self):
        self.macContext = None
        self.encContext = None
        self.seqnum = 0

    def getSeqNumBytes(self):
        w = Writer()
        w.add(self.seqnum, 8)
        self.seqnum += 1
        return w.bytes


class TLSRecordLayer(object):

    def __init__(self, sock):
        self.sock = sock

        self.session = None

        self._client = None

        self._handshakeBuffer = []
        self.clearReadBuffer()
        self.clearWriteBuffer()

        self._handshake_md5 = hashlib.md5()
        self._handshake_sha = hashlib.sha1()
        self._handshake_sha256 = hashlib.sha256()

        self.version = (0,0) #read-only
        self._versionCheck = False #Once we choose a version, this is True

        self._writeState = _ConnectionState()
        self._readState = _ConnectionState()
        self._pendingWriteState = _ConnectionState()
        self._pendingReadState = _ConnectionState()

        self.closed = True #read-only
        self._refCount = 0 #Used to trigger closure

        self.resumed = False #read-only

        self.allegedSrpUsername = None

        self.closeSocket = True

        self.ignoreAbruptClose = False

        self.fault = None

    def clearReadBuffer(self):
        pass

    def clearWriteBuffer(self):
        pass



    def read(self, max=None, min=1):
        """Read some data from the TLS connection.

        This function will block until at least 'min' bytes are
        available (or the connection is closed).

        If an exception is raised, the connection will have been
        automatically closed.

        @type max: int
        @param max: The maximum number of bytes to return.

        @type min: int
        @param min: The minimum number of bytes to return

        @rtype: str
        @return: A string of no more than 'max' bytes, and no fewer
        than 'min' (unless the connection has been closed, in which
        case fewer than 'min' bytes may be returned).

        @raise socket.error: If a socket error occurs.
        @raise tlslite.errors.TLSAbruptCloseError: If the socket is closed
        without a preceding alert.
        @raise tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        for result in self.readAsync(max, min):
            pass
        return result

    def readAsync(self, max=None, min=1):
        """Start a read operation on the TLS connection.

        This function returns a generator which behaves similarly to
        read().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or a string if the read operation has
        completed.

        @rtype: iterable
        @return: A generator; see above for details.
        """
        try:
            while len(self._readBuffer)<min and not self.closed:
                try:
                    for result in self._getMsg(ContentType.application_data):
                        if result in (0,1):
                            yield result
                    applicationData = result
                    self._readBuffer += applicationData.write()
                except TLSRemoteAlert as alert:
                    if alert.description != AlertDescription.close_notify:
                        raise
                except TLSAbruptCloseError:
                    if not self.ignoreAbruptClose:
                        raise
                    else:
                        self._shutdown(True)

            if max == None:
                max = len(self._readBuffer)

            returnBytes = self._readBuffer[:max]
            self._readBuffer = self._readBuffer[max:]
            yield bytes(returnBytes)
        except GeneratorExit:
            raise
        except:
            self._shutdown(False)
            raise

    def unread(self, b):
        pass

    def write(self, s):
        """Write some data to the TLS connection.

        This function will block until all the data has been sent.

        If an exception is raised, the connection will have been
        automatically closed.

        @type s: str
        @param s: The data to transmit to the other party.

        @raise socket.error: If a socket error occurs.
        """
        for result in self.writeAsync(s):
            pass

    def writeAsync(self, s):
        """Start a write operation on the TLS connection.

        This function returns a generator which behaves similarly to
        write().  Successive invocations of the generator will return
        1 if it is waiting to write to the socket, or will raise
        StopIteration if the write operation has completed.

        @rtype: iterable
        @return: A generator; see above for details.
        """
        try:
            if self.closed:
                raise TLSClosedConnectionError("attempt to write to closed connection")

            index = 0
            blockSize = 16384
            randomizeFirstBlock = True
            while 1:
                startIndex = index * blockSize
                endIndex = startIndex + blockSize
                if startIndex >= len(s):
                    break
                if endIndex > len(s):
                    endIndex = len(s)
                block = bytearray(s[startIndex : endIndex])
                applicationData = ApplicationData().create(block)
                for result in self._sendMsg(applicationData, \
                                            randomizeFirstBlock):
                    yield result
                randomizeFirstBlock = False #only on 1st message
                index += 1
        except GeneratorExit:
            raise
        except Exception:
            self._shutdown(self.ignoreAbruptClose)
            raise

    def close(self):
        """Close the TLS connection.

        This function will block until it has exchanged close_notify
        alerts with the other party.  After doing so, it will shut down the
        TLS connection.  Further attempts to read through this connection
        will return "".  Further attempts to write through this connection
        will raise ValueError.

        If makefile() has been called on this connection, the connection
        will be not be closed until the connection object and all file
        objects have been closed.

        Even if an exception is raised, the connection will have been
        closed.

        @raise socket.error: If a socket error occurs.
        @raise tlslite.errors.TLSAbruptCloseError: If the socket is closed
        without a preceding alert.
        @raise tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        if not self.closed:
            for result in self._decrefAsync():
                pass

    _decref_socketios = close

    def closeAsync(self):
        """Start a close operation on the TLS connection.

        This function returns a generator which behaves similarly to
        close().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or will raise StopIteration if the
        close operation has completed.

        @rtype: iterable
        @return: A generator; see above for details.
        """
        if not self.closed:
            for result in self._decrefAsync():
                yield result

    def _decrefAsync(self):
        self._refCount -= 1
        if self._refCount == 0 and not self.closed:
            try:
                for result in self._sendMsg(Alert().create(\
                        AlertDescription.close_notify, AlertLevel.warning)):
                    yield result
                alert = None
                if self.closeSocket:
                    self._shutdown(True)
                else:
                    while not alert:
                        for result in self._getMsg((ContentType.alert, \
                                                  ContentType.application_data)):
                            if result in (0,1):
                                yield result
                        if result.contentType == ContentType.alert:
                            alert = result
                    if alert.description == AlertDescription.close_notify:
                        self._shutdown(True)
                    else:
                        raise TLSRemoteAlert(alert)
            except (socket.error, TLSAbruptCloseError):
                self._shutdown(True)
            except GeneratorExit:
                raise
            except:
                self._shutdown(False)
                raise

    def getVersionName(self):
        pass
        
    def getCipherName(self):
        pass

    def getCipherImplementation(self):
        pass



    def send(self, s):
        """Send data to the TLS connection (socket emulation).

        @raise socket.error: If a socket error occurs.
        """
        self.write(s)
        return len(s)

    def sendall(self, s):
        pass

    def recv(self, bufsize):
        """Get some data from the TLS connection (socket emulation).

        @raise socket.error: If a socket error occurs.
        @raise tlslite.errors.TLSAbruptCloseError: If the socket is closed
        without a preceding alert.
        @raise tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        return self.read(bufsize)

    def recv_into(self, b):
        pass

    def makefile(self, mode='r', bufsize=-1):
        pass

    def getsockname(self):
        pass

    def getpeername(self):
        pass

    def settimeout(self, value):
        pass

    def gettimeout(self):
        pass

    def setsockopt(self, level, optname, value):
        pass

    def shutdown(self, how):
        pass
    	
    def fileno(self):
        """Not implement in TLS Lite."""
        raise NotImplementedError()
    	


    def _shutdown(self, resumable):
        self._writeState = _ConnectionState()
        self._readState = _ConnectionState()
        self.version = (0,0)
        self._versionCheck = False
        self.closed = True
        if self.closeSocket:
            self.sock.close()

        if not resumable and self.session:
            self.session.resumable = False


    def _sendError(self, alertDescription, errorStr=None):
        alert = Alert().create(alertDescription, AlertLevel.fatal)
        for result in self._sendMsg(alert):
            yield result
        self._shutdown(False)
        raise TLSLocalAlert(alert, errorStr)

    def _sendMsgs(self, msgs):
        pass

    def _sendMsg(self, msg, randomizeFirstBlock = True):
        if not self.closed and randomizeFirstBlock and self.version <= (3,1) \
                and self._writeState.encContext \
                and self._writeState.encContext.isBlockCipher \
                and isinstance(msg, ApplicationData):
            msgFirstByte = msg.splitFirstByte()
            for result in self._sendMsg(msgFirstByte,
                                       randomizeFirstBlock = False):
                yield result                                            

        b = msg.write()
        
        if len(b) == 0:
            return
            
        contentType = msg.contentType

        if contentType == ContentType.handshake:
            self._handshake_md5.update(compat26Str(b))
            self._handshake_sha.update(compat26Str(b))
            self._handshake_sha256.update(compat26Str(b))

        if self._writeState.macContext:
            seqnumBytes = self._writeState.getSeqNumBytes()
            mac = self._writeState.macContext.copy()
            mac.update(compatHMAC(seqnumBytes))
            mac.update(compatHMAC(bytearray([contentType])))
            if self.version == (3,0):
                mac.update( compatHMAC( bytearray([len(b)//256] )))
                mac.update( compatHMAC( bytearray([len(b)%256] )))
            elif self.version in ((3,1), (3,2), (3,3)):
                mac.update(compatHMAC( bytearray([self.version[0]] )))
                mac.update(compatHMAC( bytearray([self.version[1]] )))
                mac.update( compatHMAC( bytearray([len(b)//256] )))
                mac.update( compatHMAC( bytearray([len(b)%256] )))
            else:
                raise AssertionError()
            mac.update(compatHMAC(b))
            macBytes = bytearray(mac.digest())
            if self.fault == Fault.badMAC:
                macBytes[0] = (macBytes[0]+1) % 256

        if self._writeState.encContext:
            if self._writeState.encContext.isBlockCipher:

                if self.version >= (3,2):
                    b = self.fixedIVBlock + b

                currentLength = len(b) + len(macBytes)
                blockLength = self._writeState.encContext.block_size
                paddingLength = blockLength - 1 - (currentLength % blockLength)

                paddingBytes = bytearray([paddingLength] * (paddingLength+1))
                if self.fault == Fault.badPadding:
                    paddingBytes[0] = (paddingBytes[0]+1) % 256
                endBytes = macBytes + paddingBytes
                b += endBytes
                b = self._writeState.encContext.encrypt(b)

            else:
                b += macBytes
                b = self._writeState.encContext.encrypt(b)

        r = RecordHeader3().create(self.version, contentType, len(b))
        s = r.write() + b
        while 1:
            try:
                bytesSent = self.sock.send(s) #Might raise socket.error
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 1
                    continue
                else:
                    if contentType == ContentType.handshake:
                        
                        for result in self._getNextRecord():
                            if result in (0,1):
                                yield result
                                
                        self._shutdown(False)
                        
                        recordHeader, p = result                        
                        if recordHeader.type == ContentType.alert:
                            alert = Alert().parse(p)
                            raise TLSRemoteAlert(alert)
                    else:
                        raise
            if bytesSent == len(s):
                return
            s = s[bytesSent:]
            yield 1


    def _getMsg(self, expectedType, secondaryType=None, constructorType=None):
        try:
            if not isinstance(expectedType, tuple):
                expectedType = (expectedType,)

            while 1:
                for result in self._getNextRecord():
                    if result in (0,1):
                        yield result
                recordHeader, p = result

                if recordHeader.type == ContentType.application_data:
                    if p.index == len(p.bytes):
                        continue

                if recordHeader.type not in expectedType:

                    if recordHeader.type == ContentType.alert:
                        alert = Alert().parse(p)

                        if alert.level == AlertLevel.warning or \
                           alert.description == AlertDescription.close_notify:

                            try:
                                alertMsg = Alert()
                                alertMsg.create(AlertDescription.close_notify,
                                                AlertLevel.warning)
                                for result in self._sendMsg(alertMsg):
                                    yield result
                            except socket.error:
                                pass

                            if alert.description == \
                                   AlertDescription.close_notify:
                                self._shutdown(True)
                            elif alert.level == AlertLevel.warning:
                                self._shutdown(False)

                        else: #Fatal alert:
                            self._shutdown(False)

                        raise TLSRemoteAlert(alert)

                    if recordHeader.type == ContentType.handshake:
                        subType = p.get(1)
                        reneg = False
                        if self._client:
                            if subType == HandshakeType.hello_request:
                                reneg = True
                        else:
                            if subType == HandshakeType.client_hello:
                                reneg = True
                        if reneg:
                            alertMsg = Alert()
                            alertMsg.create(AlertDescription.no_renegotiation,
                                            AlertLevel.warning)
                            for result in self._sendMsg(alertMsg):
                                yield result
                            continue

                    for result in self._sendError(\
                            AlertDescription.unexpected_message,
                            "received type=%d" % recordHeader.type):
                        yield result

                break

            if recordHeader.type == ContentType.change_cipher_spec:
                yield ChangeCipherSpec().parse(p)
            elif recordHeader.type == ContentType.alert:
                yield Alert().parse(p)
            elif recordHeader.type == ContentType.application_data:
                yield ApplicationData().parse(p)
            elif recordHeader.type == ContentType.handshake:
                if not isinstance(secondaryType, tuple):
                    secondaryType = (secondaryType,)

                if recordHeader.ssl2:
                    subType = p.get(1)
                    if subType != HandshakeType.client_hello:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message,
                                "Can only handle SSLv2 ClientHello messages"):
                            yield result
                    if HandshakeType.client_hello not in secondaryType:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message):
                            yield result
                    subType = HandshakeType.client_hello
                else:
                    subType = p.get(1)
                    if subType not in secondaryType:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message,
                                "Expecting %s, got %s" % (str(secondaryType), subType)):
                            yield result

                self._handshake_md5.update(compat26Str(p.bytes))
                self._handshake_sha.update(compat26Str(p.bytes))
                self._handshake_sha256.update(compat26Str(p.bytes))

                if subType == HandshakeType.client_hello:
                    yield ClientHello(recordHeader.ssl2).parse(p)
                elif subType == HandshakeType.server_hello:
                    yield ServerHello().parse(p)
                elif subType == HandshakeType.certificate:
                    yield Certificate(constructorType).parse(p)
                elif subType == HandshakeType.certificate_request:
                    yield CertificateRequest(self.version).parse(p)
                elif subType == HandshakeType.certificate_verify:
                    yield CertificateVerify(self.version).parse(p)
                elif subType == HandshakeType.server_key_exchange:
                    yield ServerKeyExchange(constructorType).parse(p)
                elif subType == HandshakeType.server_hello_done:
                    yield ServerHelloDone().parse(p)
                elif subType == HandshakeType.client_key_exchange:
                    yield ClientKeyExchange(constructorType, \
                                            self.version).parse(p)
                elif subType == HandshakeType.finished:
                    yield Finished(self.version).parse(p)
                elif subType == HandshakeType.next_protocol:
                    yield NextProtocol().parse(p)
                else:
                    raise AssertionError()

        except SyntaxError as e:
            for result in self._sendError(AlertDescription.decode_error,
                                         formatExceptionTrace(e)):
                yield result


    def _getNextRecord(self):

        if self._handshakeBuffer:
            recordHeader, b = self._handshakeBuffer[0]
            self._handshakeBuffer = self._handshakeBuffer[1:]
            yield (recordHeader, Parser(b))
            return

        b = bytearray(0)
        recordHeaderLength = 1
        ssl2 = False
        while 1:
            try:
                s = self.sock.recv(recordHeaderLength-len(b))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                    continue
                else:
                    raise

            if len(s)==0:
                raise TLSAbruptCloseError()

            b += bytearray(s)
            if len(b)==1:
                if b[0] in ContentType.all:
                    ssl2 = False
                    recordHeaderLength = 5
                elif b[0] == 128:
                    ssl2 = True
                    recordHeaderLength = 2
                else:
                    raise SyntaxError()
            if len(b) == recordHeaderLength:
                break

        if ssl2:
            r = RecordHeader2().parse(Parser(b))
        else:
            r = RecordHeader3().parse(Parser(b))

        if r.length > 18432:
            for result in self._sendError(AlertDescription.record_overflow):
                yield result

        b = bytearray(0)
        while 1:
            try:
                s = self.sock.recv(r.length - len(b))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                    continue
                else:
                    raise

            if len(s)==0:
                    raise TLSAbruptCloseError()

            b += bytearray(s)
            if len(b) == r.length:
                break


        for result in self._decryptRecord(r.type, b):
            if result in (0,1): yield result
            else: break
        b = result
        p = Parser(b)

        if r.type != ContentType.handshake:
            yield (r, p)
        elif r.ssl2:
            yield (r, p)
        else:
            while 1:
                if p.index == len(b): #If we're at the end
                    if not self._handshakeBuffer:
                        for result in self._sendError(\
                                AlertDescription.decode_error, \
                                "Received empty handshake record"):
                            yield result
                    break
                if p.index+4 > len(b):
                    for result in self._sendError(\
                            AlertDescription.decode_error,
                            "A record has a partial handshake message (1)"):
                        yield result
                p.get(1) # skip handshake type
                msgLength = p.get(3)
                if p.index+msgLength > len(b):
                    for result in self._sendError(\
                            AlertDescription.decode_error,
                            "A record has a partial handshake message (2)"):
                        yield result

                handshakePair = (r, b[p.index-4 : p.index+msgLength])
                self._handshakeBuffer.append(handshakePair)
                p.index += msgLength

            recordHeader, b = self._handshakeBuffer[0]
            self._handshakeBuffer = self._handshakeBuffer[1:]
            yield (recordHeader, Parser(b))


    def _decryptRecord(self, recordType, b):
        if self._readState.encContext:

            if self._readState.encContext.isBlockCipher:
                blockLength = self._readState.encContext.block_size
                if len(b) % blockLength != 0:
                    for result in self._sendError(\
                            AlertDescription.decryption_failed,
                            "Encrypted data not a multiple of blocksize"):
                        yield result
                b = self._readState.encContext.decrypt(b)
                if self.version >= (3,2): #For TLS 1.1, remove explicit IV
                    b = b[self._readState.encContext.block_size : ]

                if len(b) == 0:
                    for result in self._sendError(\
                            AlertDescription.decryption_failed,
                            "No data left after decryption and IV removal"):
                        yield result

                paddingGood = True
                paddingLength = b[-1]
                if (paddingLength+1) > len(b):
                    paddingGood=False
                    totalPaddingLength = 0
                else:
                    if self.version == (3,0):
                        totalPaddingLength = paddingLength+1
                    elif self.version in ((3,1), (3,2), (3,3)):
                        totalPaddingLength = paddingLength+1
                        paddingBytes = b[-totalPaddingLength:-1]
                        for byte in paddingBytes:
                            if byte != paddingLength:
                                paddingGood = False
                                totalPaddingLength = 0
                    else:
                        raise AssertionError()

            else:
                paddingGood = True
                b = self._readState.encContext.decrypt(b)
                totalPaddingLength = 0

            macGood = True
            macLength = self._readState.macContext.digest_size
            endLength = macLength + totalPaddingLength
            if endLength > len(b):
                macGood = False
            else:
                startIndex = len(b) - endLength
                endIndex = startIndex + macLength
                checkBytes = b[startIndex : endIndex]

                seqnumBytes = self._readState.getSeqNumBytes()
                b = b[:-endLength]
                mac = self._readState.macContext.copy()
                mac.update(compatHMAC(seqnumBytes))
                mac.update(compatHMAC(bytearray([recordType])))
                if self.version == (3,0):
                    mac.update( compatHMAC(bytearray( [len(b)//256] ) ))
                    mac.update( compatHMAC(bytearray( [len(b)%256] ) ))
                elif self.version in ((3,1), (3,2), (3,3)):
                    mac.update(compatHMAC(bytearray( [self.version[0]] ) ))
                    mac.update(compatHMAC(bytearray( [self.version[1]] ) ))
                    mac.update(compatHMAC(bytearray( [len(b)//256] ) ))
                    mac.update(compatHMAC(bytearray( [len(b)%256] ) ))
                else:
                    raise AssertionError()
                mac.update(compatHMAC(b))
                macBytes = bytearray(mac.digest())

                if macBytes != checkBytes:
                    macGood = False

            if not (paddingGood and macGood):
                for result in self._sendError(AlertDescription.bad_record_mac,
                                          "MAC failure (or padding failure)"):
                    yield result

        yield b

    def _handshakeStart(self, client):
        pass

    def _handshakeDone(self, resumed):
        pass

    def _calcPendingStates(self, cipherSuite, masterSecret,
            clientRandom, serverRandom, implementations):
        pass

    def _changeWriteState(self):
        pass

    def _changeReadState(self):
        pass

    def _calcSSLHandshakeHash(self, masterSecret, label):
        pass

