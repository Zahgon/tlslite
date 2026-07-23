

from .utils.compat import *
from .utils.cryptomath import *
from .errors import *
from .utils.codec import *
from .constants import *
from .x509 import X509
from .x509certchain import X509CertChain
from .utils.tackwrapper import *
from .extensions import *

class RecordHeader3(object):
    def __init__(self):
        self.type = 0
        self.version = (0,0)
        self.length = 0
        self.ssl2 = False

    def create(self, version, type, length):
        self.type = type
        self.version = version
        self.length = length
        return self

    def write(self):
        w = Writer()
        w.add(self.type, 1)
        w.add(self.version[0], 1)
        w.add(self.version[1], 1)
        w.add(self.length, 2)
        return w.bytes

    def parse(self, p):
        self.type = p.get(1)
        self.version = (p.get(1), p.get(1))
        self.length = p.get(2)
        self.ssl2 = False
        return self

    @property
    def typeName(self):
        pass

    def __str__(self):
        return "SSLv3 record,version({0[0]}.{0[1]}),"\
                "content type({1}),length({2})".format(self.version,
                        self.typeName, self.length)

    def __repr__(self):
        return "RecordHeader3(type={0}, version=({1[0]}.{1[1]}), length={2})".\
                format(self.type, self.version, self.length)

class RecordHeader2(object):
    def __init__(self):
        self.type = 0
        self.version = (0,0)
        self.length = 0
        self.ssl2 = True

    def parse(self, p):
        if p.get(1)!=128:
            raise SyntaxError()
        self.type = ContentType.handshake
        self.version = (2,0)
        self.length = p.get(1)
        return self


class Alert(object):
    def __init__(self):
        self.contentType = ContentType.alert
        self.level = 0
        self.description = 0

    def create(self, description, level=AlertLevel.fatal):
        self.level = level
        self.description = description
        return self

    def parse(self, p):
        p.setLengthCheck(2)
        self.level = p.get(1)
        self.description = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.level, 1)
        w.add(self.description, 1)
        return w.bytes

    @property
    def levelName(self):
        pass

    @property
    def descriptionName(self):
        pass

    def __str__(self):
        return "Alert, level:{0}, description:{1}".format(self.levelName,
                self.descriptionName)

    def __repr__(self):
        return "Alert(level={0}, description={1})".format(self.level,
                self.description)

class HandshakeMsg(object):
    def __init__(self, handshakeType):
        self.contentType = ContentType.handshake
        self.handshakeType = handshakeType
    
    def postWrite(self, w):
        headerWriter = Writer()
        headerWriter.add(self.handshakeType, 1)
        headerWriter.add(len(w.bytes), 3)
        return headerWriter.bytes + w.bytes

class ClientHello(HandshakeMsg):
    def __init__(self, ssl2=False):
        HandshakeMsg.__init__(self, HandshakeType.client_hello)
        self.ssl2 = ssl2
        self.client_version = (0,0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []         # a list of 16-bit values
        self.compression_methods = []   # a list of 8-bit values
        self.extensions = None

    def __str__(self):
        """
        Return human readable representation of Client Hello

        @rtype: str
        """

        if self.session_id.count(bytearray(b'\x00')) == len(self.session_id)\
            and len(self.session_id) != 0:
            session = "bytearray(b'\\x00'*{0})".format(len(self.session_id))
        else:
            session = repr(self.session_id)
        ret = "client_hello,version({0[0]}.{0[1]}),random(...),"\
                "session ID({1!s}),cipher suites({2!r}),"\
                "compression methods({3!r})".format(
                        self.client_version, session,
                        self.cipher_suites, self.compression_methods)

        if self.extensions is not None:
            ret += ",extensions({0!r})".format(self.extensions)

        return ret

    def __repr__(self):
        """
        Return machine readable representation of Client Hello

        @rtype: str
        """
        return "ClientHello(ssl2={0}, client_version=({1[0]}.{1[1]}), "\
                "random={2!r}, session_id={3!r}, cipher_suites={4!r}, "\
                "compression_methods={5}, extensions={6})".format(\
                self.ssl2, self.client_version, self.random, self.session_id,
                self.cipher_suites, self.compression_methods, self.extensions)

    def getExtension(self, extType):
        pass

    def addExtension(self, ext):
        pass

    @property
    def certificate_types(self):
        pass

    @certificate_types.setter
    def certificate_types(self, val):
        pass

    @property
    def srp_username(self):
        pass

    @srp_username.setter
    def srp_username(self, name):
        pass

    @property
    def tack(self):
        pass

    @tack.setter
    def tack(self, present):
        pass

    @property
    def supports_npn(self):
        pass

    @supports_npn.setter
    def supports_npn(self, present):
        pass

    @property
    def server_name(self):
        pass

    @server_name.setter
    def server_name(self, hostname):
        pass

    def create(self, version, random, session_id, cipher_suites,
               certificate_types=None, srpUsername=None,
               tack=False, supports_npn=False, serverName=None,
               extensions=None):
        """
        Create a ClientHello message for sending.

        @type version: tuple
        @param version: the highest supported TLS version encoded as two int
            tuple

        @type random: bytearray
        @param random: client provided random value, in old versions of TLS
            (before 1.2) the first 32 bits should include system time

        @type session_id: bytearray
        @param session_id: ID of session, set when doing session resumption

        @type cipher_suites: list
        @param cipher_suites: list of ciphersuites advertised as supported

        @type certificate_types: list
        @param certificate_types: list of supported certificate types, uses
            TLS extension for signalling, as such requires TLS1.0 to work

        @type srpUsername: bytearray
        @param srpUsername: utf-8 encoded username for SRP, TLS extension

        @type tack: boolean
        @param tack: whatever to advertise support for TACK, TLS extension

        @type supports_npn: boolean
        @param supports_npn: whatever to advertise support for NPN, TLS
            extension

        @type serverName: bytearray
        @param serverName: the hostname to request in server name indication
            extension, TLS extension. Note that SNI allows to set multiple
            hostnames and values that are not hostnames, use L{SNIExtension}
            together with L{extensions} to use it.

        @type extensions: list of L{TLSExtension}
        @param extensions: list of extensions to advertise
        """
        self.client_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suites = cipher_suites
        self.compression_methods = [0]
        if not extensions is None:
            self.extensions = extensions
        if not certificate_types is None:
            self.certificate_types = certificate_types
        if not srpUsername is None:
            self.srp_username = bytearray(srpUsername, "utf-8")
        self.tack = tack
        self.supports_npn = supports_npn
        if not serverName is None:
            self.server_name = bytearray(serverName, "utf-8")
        return self

    def parse(self, p):
        if self.ssl2:
            self.client_version = (p.get(1), p.get(1))
            cipherSpecsLength = p.get(2)
            sessionIDLength = p.get(2)
            randomLength = p.get(2)
            self.cipher_suites = p.getFixList(3, cipherSpecsLength//3)
            self.session_id = p.getFixBytes(sessionIDLength)
            self.random = p.getFixBytes(randomLength)
            if len(self.random) < 32:
                zeroBytes = 32-len(self.random)
                self.random = bytearray(zeroBytes) + self.random
            self.compression_methods = [0]#Fake this value

        else:
            p.startLengthCheck(3)
            self.client_version = (p.get(1), p.get(1))
            self.random = p.getFixBytes(32)
            self.session_id = p.getVarBytes(1)
            self.cipher_suites = p.getVarList(2, 2)
            self.compression_methods = p.getVarList(1, 1)
            if not p.atLengthCheck():
                self.extensions = []
                totalExtLength = p.get(2)
                while not p.atLengthCheck():
                    ext = TLSExtension().parse(p)
                    self.extensions += [ext]
            p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.client_version[0], 1)
        w.add(self.client_version[1], 1)
        w.addFixSeq(self.random, 1)
        w.addVarSeq(self.session_id, 1, 1)
        w.addVarSeq(self.cipher_suites, 2, 2)
        w.addVarSeq(self.compression_methods, 1, 1)

        if not self.extensions is None:
            w2 = Writer()
            for ext in self.extensions:
                w2.bytes += ext.write()

            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        return self.postWrite(w)

class ServerHello(HandshakeMsg):
    def __init__(self):
        """Initialise ServerHello object"""

        HandshakeMsg.__init__(self, HandshakeType.server_hello)
        self.server_version = (0,0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suite = 0
        self.compression_method = 0
        self._tack_ext = None
        self.extensions = None

    def __str__(self):
        base = "server_hello,length({0}),version({1[0]}.{1[1]}),random(...),"\
                "session ID({2!r}),cipher({3:#x}),compression method({4})"\
                .format(len(self.write())-4, self.server_version,
                        self.session_id, self.cipher_suite,
                        self.compression_method)

        if self.extensions is None:
            return base

        ret = ",extensions["
        ret += ",".join(repr(x) for x in self.extensions)
        ret += "]"
        return base + ret

    def __repr__(self):
        return "ServerHello(server_version=({0[0]}.{0[1]}), random={1!r}, "\
                "session_id={2!r}, cipher_suite={3}, compression_method={4}, "\
                "_tack_ext={5}, extensions={6!r})".format(\
                self.server_version, self.random, self.session_id,
                self.cipher_suite, self.compression_method, self._tack_ext,
                self.extensions)

    def getExtension(self, extType):
        pass

    def addExtension(self, ext):
        pass

    @property
    def tackExt(self):
        pass

    @tackExt.setter
    def tackExt(self, val):
        pass

    @property
    def certificate_type(self):
        pass

    @certificate_type.setter
    def certificate_type(self, val):
        pass

    @property
    def next_protos(self):
        pass

    @next_protos.setter
    def next_protos(self, val):
        pass

    @property
    def next_protos_advertised(self):
        pass

    @next_protos_advertised.setter
    def next_protos_advertised(self, val):
        pass

    def create(self, version, random, session_id, cipher_suite,
               certificate_type, tackExt, next_protos_advertised,
               extensions=None):
        self.extensions = extensions
        self.server_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.certificate_type = certificate_type
        self.compression_method = 0
        self.tackExt = tackExt
        self.next_protos_advertised = next_protos_advertised
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.server_version = (p.get(1), p.get(1))
        self.random = p.getFixBytes(32)
        self.session_id = p.getVarBytes(1)
        self.cipher_suite = p.get(2)
        self.compression_method = p.get(1)
        if not p.atLengthCheck():
            self.extensions = []
            totalExtLength = p.get(2)
            p2 = Parser(p.getFixBytes(totalExtLength))
            while p2.getRemainingLength() > 0:
                ext = TLSExtension(server=True).parse(p2)
                self.extensions += [ext]
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.server_version[0], 1)
        w.add(self.server_version[1], 1)
        w.addFixSeq(self.random, 1)
        w.addVarSeq(self.session_id, 1, 1)
        w.add(self.cipher_suite, 2)
        w.add(self.compression_method, 1)

        if not self.extensions is None:
            w2 = Writer()
            for ext in self.extensions:
                w2.bytes += ext.write()

            if self.tackExt:
                b = self.tackExt.serialize()
                w2.add(ExtensionType.tack, 2)
                w2.add(len(b), 2)
                w2.bytes += b

            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes        
        return self.postWrite(w)

class Certificate(HandshakeMsg):
    def __init__(self, certificateType):
        HandshakeMsg.__init__(self, HandshakeType.certificate)
        self.certificateType = certificateType
        self.certChain = None

    def create(self, certChain):
        self.certChain = certChain
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.certificateType == CertificateType.x509:
            chainLength = p.get(3)
            index = 0
            certificate_list = []
            while index != chainLength:
                certBytes = p.getVarBytes(3)
                x509 = X509()
                x509.parseBinary(certBytes)
                certificate_list.append(x509)
                index += len(certBytes)+3
            if certificate_list:
                self.certChain = X509CertChain(certificate_list)
        else:
            raise AssertionError()

        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.certificateType == CertificateType.x509:
            chainLength = 0
            if self.certChain:
                certificate_list = self.certChain.x509List
            else:
                certificate_list = []
            for cert in certificate_list:
                bytes = cert.writeBytes()
                chainLength += len(bytes)+3
            w.add(chainLength, 3)
            for cert in certificate_list:
                bytes = cert.writeBytes()
                w.addVarSeq(bytes, 1, 3)
        else:
            raise AssertionError()
        return self.postWrite(w)

class CertificateRequest(HandshakeMsg):
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.certificate_request)
        self.certificate_types = []
        self.certificate_authorities = []
        self.version = version
        self.supported_signature_algs = []

    def create(self, certificate_types, certificate_authorities, sig_algs=()):
        self.certificate_types = certificate_types
        self.certificate_authorities = certificate_authorities
        self.supported_signature_algs = sig_algs
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.certificate_types = p.getVarList(1, 1)
        if self.version >= (3,3):
            self.supported_signature_algs = \
                [(b >> 8, b & 0xff) for b in p.getVarList(2, 2)]
        ca_list_length = p.get(2)
        index = 0
        self.certificate_authorities = []
        while index != ca_list_length:
          ca_bytes = p.getVarBytes(2)
          self.certificate_authorities.append(ca_bytes)
          index += len(ca_bytes)+2
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addVarSeq(self.certificate_types, 1, 1)
        if self.version >= (3,3):
            w2 = Writer()
            for (hash_alg, signature) in self.supported_signature_algs:
                w2.add(hash_alg, 1)
                w2.add(signature, 1)
            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        caLength = 0
        for ca_dn in self.certificate_authorities:
            caLength += len(ca_dn)+2
        w.add(caLength, 2)
        for ca_dn in self.certificate_authorities:
            w.addVarSeq(ca_dn, 1, 2)
        return self.postWrite(w)

class ServerKeyExchange(HandshakeMsg):
    def __init__(self, cipherSuite):
        HandshakeMsg.__init__(self, HandshakeType.server_key_exchange)
        self.cipherSuite = cipherSuite
        self.srp_N = 0
        self.srp_g = 0
        self.srp_s = bytearray(0)
        self.srp_B = 0
        self.dh_p = 0
        self.dh_g = 0
        self.dh_Ys = 0
        self.signature = bytearray(0)

    def createSRP(self, srp_N, srp_g, srp_s, srp_B):
        pass
    
    def createDH(self, dh_p, dh_g, dh_Ys):
        pass

    def parse(self, p):
        p.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_N = bytesToNumber(p.getVarBytes(2))
            self.srp_g = bytesToNumber(p.getVarBytes(2))
            self.srp_s = p.getVarBytes(1)
            self.srp_B = bytesToNumber(p.getVarBytes(2))
            if self.cipherSuite in CipherSuite.srpCertSuites:
                self.signature = p.getVarBytes(2)
        elif self.cipherSuite in CipherSuite.anonSuites:
            self.dh_p = bytesToNumber(p.getVarBytes(2))
            self.dh_g = bytesToNumber(p.getVarBytes(2))
            self.dh_Ys = bytesToNumber(p.getVarBytes(2))
        p.stopLengthCheck()
        return self

    def write(self, writeSig=True):
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToByteArray(self.srp_N), 1, 2)
            w.addVarSeq(numberToByteArray(self.srp_g), 1, 2)
            w.addVarSeq(self.srp_s, 1, 1)
            w.addVarSeq(numberToByteArray(self.srp_B), 1, 2)
            if self.cipherSuite in CipherSuite.srpCertSuites and writeSig:
                w.addVarSeq(self.signature, 1, 2)
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToByteArray(self.dh_p), 1, 2)
            w.addVarSeq(numberToByteArray(self.dh_g), 1, 2)
            w.addVarSeq(numberToByteArray(self.dh_Ys), 1, 2)
            if self.cipherSuite in [] and writeSig: # TODO support for signed_params
                w.addVarSeq(self.signature, 1, 2)
        return self.postWrite(w)

    def hash(self, clientRandom, serverRandom):
        pass

class ServerHelloDone(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello_done)

    def create(self):
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        return self.postWrite(w)

class ClientKeyExchange(HandshakeMsg):
    def __init__(self, cipherSuite, version=None):
        HandshakeMsg.__init__(self, HandshakeType.client_key_exchange)
        self.cipherSuite = cipherSuite
        self.version = version
        self.srp_A = 0
        self.encryptedPreMasterSecret = bytearray(0)

    def createSRP(self, srp_A):
        pass

    def createRSA(self, encryptedPreMasterSecret):
        pass
    
    def createDH(self, dh_Yc):
        pass
    
    def parse(self, p):
        p.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_A = bytesToNumber(p.getVarBytes(2))
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3,1), (3,2), (3,3)):
                self.encryptedPreMasterSecret = p.getVarBytes(2)
            elif self.version == (3,0):
                self.encryptedPreMasterSecret = \
                    p.getFixBytes(len(p.bytes)-p.index)
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.anonSuites:
            self.dh_Yc = bytesToNumber(p.getVarBytes(2))            
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToByteArray(self.srp_A), 1, 2)
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3,1), (3,2), (3,3)):
                w.addVarSeq(self.encryptedPreMasterSecret, 1, 2)
            elif self.version == (3,0):
                w.addFixSeq(self.encryptedPreMasterSecret, 1)
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToByteArray(self.dh_Yc), 1, 2)            
        else:
            raise AssertionError()
        return self.postWrite(w)

class CertificateVerify(HandshakeMsg):
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.certificate_verify)
        self.version = version
        self.signature_algorithm = None
        self.signature = bytearray(0)

    def create(self, signature_algorithm, signature):
        self.signature_algorithm = signature_algorithm
        self.signature = signature
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.version >= (3,3):
            self.signature_algorithm = (p.get(1), p.get(1))
        self.signature = p.getVarBytes(2)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.version >= (3,3):
            w.add(self.signature_algorithm[0], 1)
            w.add(self.signature_algorithm[1], 1)
        w.addVarSeq(self.signature, 1, 2)
        return self.postWrite(w)

class ChangeCipherSpec(object):
    def __init__(self):
        self.contentType = ContentType.change_cipher_spec
        self.type = 1

    def create(self):
        self.type = 1
        return self

    def parse(self, p):
        p.setLengthCheck(1)
        self.type = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.type,1)
        return w.bytes


class NextProtocol(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.next_protocol)
        self.next_proto = None

    def create(self, next_proto):
        self.next_proto = next_proto
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.next_proto = p.getVarBytes(1)
        _ = p.getVarBytes(1)
        p.stopLengthCheck()
        return self

    def write(self, trial=False):
        w = Writer()
        w.addVarSeq(self.next_proto, 1, 1)
        paddingLen = 32 - ((len(self.next_proto) + 2) % 32)
        w.addVarSeq(bytearray(paddingLen), 1, 1)
        return self.postWrite(w)

class Finished(HandshakeMsg):
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.finished)
        self.version = version
        self.verify_data = bytearray(0)

    def create(self, verify_data):
        self.verify_data = verify_data
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.version == (3,0):
            self.verify_data = p.getFixBytes(36)
        elif self.version in ((3,1), (3,2), (3,3)):
            self.verify_data = p.getFixBytes(12)
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addFixSeq(self.verify_data, 1)
        return self.postWrite(w)

class ApplicationData(object):
    def __init__(self):
        self.contentType = ContentType.application_data
        self.bytes = bytearray(0)

    def create(self, bytes):
        self.bytes = bytes
        return self
        
    def splitFirstByte(self):
        newMsg = ApplicationData().create(self.bytes[:1])
        self.bytes = self.bytes[1:]
        return newMsg

    def parse(self, p):
        self.bytes = p.bytes
        return self

    def write(self):
        return self.bytes
