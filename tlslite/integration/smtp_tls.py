

from smtplib import SMTP
from tlslite.tlsconnection import TLSConnection
from tlslite.integration.clienthelper import ClientHelper

class SMTP_TLS(SMTP):

    def starttls(self,
                 username=None, password=None,
                 certChain=None, privateKey=None,
                 checker=None,
                 settings=None):
        pass
