

from .utils.cryptomath import *
from .utils.compat import *
from tlslite import mathtls
from .basedb import BaseDB

class VerifierDB(BaseDB):
    def __init__(self, filename=None):
        """Create a new VerifierDB instance.

        @type filename: str
        @param filename: Filename for an on-disk database, or None for
        an in-memory database.  If the filename already exists, follow
        this with a call to open().  To create a new on-disk database,
        follow this with a call to create().
        """
        BaseDB.__init__(self, filename, "verifier")

    def _getItem(self, username, valueStr):
        pass

    def __setitem__(self, username, verifierEntry):
        """Add a verifier entry to the database.

        @type username: str
        @param username: The username to associate the verifier with.
        Must be less than 256 characters in length.  Must not already
        be in the database.

        @type verifierEntry: tuple
        @param verifierEntry: The verifier entry to add.  Use
        L{tlslite.verifierdb.VerifierDB.makeVerifier} to create a
        verifier entry.
        """
        BaseDB.__setitem__(self, username, verifierEntry)


    def _setItem(self, username, value):
        pass

    def _checkItem(self, value, username, param):
        pass


    def makeVerifier(username, password, bits):
        pass
    makeVerifier = staticmethod(makeVerifier)
