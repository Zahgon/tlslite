
import socket

from .constants import AlertDescription, AlertLevel

class TLSError(Exception):
    
    def __str__(self):
        """"At least print out the Exception time for str(...)."""
        return repr(self)    

class TLSClosedConnectionError(TLSError, socket.error):
    pass

class TLSAbruptCloseError(TLSError):
    pass

class TLSAlert(TLSError):
    pass

    _descriptionStr = {\
        AlertDescription.close_notify: "close_notify",\
        AlertDescription.unexpected_message: "unexpected_message",\
        AlertDescription.bad_record_mac: "bad_record_mac",\
        AlertDescription.decryption_failed: "decryption_failed",\
        AlertDescription.record_overflow: "record_overflow",\
        AlertDescription.decompression_failure: "decompression_failure",\
        AlertDescription.handshake_failure: "handshake_failure",\
        AlertDescription.no_certificate: "no certificate",\
        AlertDescription.bad_certificate: "bad_certificate",\
        AlertDescription.unsupported_certificate: "unsupported_certificate",\
        AlertDescription.certificate_revoked: "certificate_revoked",\
        AlertDescription.certificate_expired: "certificate_expired",\
        AlertDescription.certificate_unknown: "certificate_unknown",\
        AlertDescription.illegal_parameter: "illegal_parameter",\
        AlertDescription.unknown_ca: "unknown_ca",\
        AlertDescription.access_denied: "access_denied",\
        AlertDescription.decode_error: "decode_error",\
        AlertDescription.decrypt_error: "decrypt_error",\
        AlertDescription.export_restriction: "export_restriction",\
        AlertDescription.protocol_version: "protocol_version",\
        AlertDescription.insufficient_security: "insufficient_security",\
        AlertDescription.internal_error: "internal_error",\
        AlertDescription.inappropriate_fallback: "inappropriate_fallback",\
        AlertDescription.user_canceled: "user_canceled",\
        AlertDescription.no_renegotiation: "no_renegotiation",\
        AlertDescription.unknown_psk_identity: "unknown_psk_identity"}

class TLSLocalAlert(TLSAlert):
    def __init__(self, alert, message=None):
        self.description = alert.description
        self.level = alert.level
        self.message = message

    def __str__(self):
        alertStr = TLSAlert._descriptionStr.get(self.description)
        if alertStr == None:
            alertStr = str(self.description)
        if self.message:
            return alertStr + ": " + self.message
        else:
            return alertStr

class TLSRemoteAlert(TLSAlert):
    def __init__(self, alert):
        self.description = alert.description
        self.level = alert.level

    def __str__(self):
        alertStr = TLSAlert._descriptionStr.get(self.description)
        if alertStr == None:
            alertStr = str(self.description)
        return alertStr

class TLSAuthenticationError(TLSError):
    pass

class TLSNoAuthenticationError(TLSAuthenticationError):
    pass

class TLSAuthenticationTypeError(TLSAuthenticationError):
    pass

class TLSFingerprintError(TLSAuthenticationError):
    pass

class TLSAuthorizationError(TLSAuthenticationError):
    pass

class TLSValidationError(TLSAuthenticationError):
    def __init__(self, msg, info=None):
        TLSAuthenticationError.__init__(self, msg)
        self.info = info

class TLSFaultError(TLSError):
    pass


class TLSUnsupportedError(TLSError):
    pass

class TLSInternalError(TLSError):
    pass
