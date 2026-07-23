

import threading
import time

class SessionCache(object):


    def __init__(self, maxEntries=10000, maxAge=14400):
        """Create a new SessionCache.

        @type maxEntries: int
        @param maxEntries: The maximum size of the cache.  When this
        limit is reached, the oldest sessions will be deleted as
        necessary to make room for new ones.  The default is 10000.

        @type maxAge: int
        @param maxAge:  The number of seconds before a session expires
        from the cache.  The default is 14400 (i.e. 4 hours)."""

        self.lock = threading.Lock()

        self.entriesDict = {}

        self.entriesList = [(None,None)] * maxEntries

        self.firstIndex = 0
        self.lastIndex = 0
        self.maxAge = maxAge

    def __getitem__(self, sessionID):
        self.lock.acquire()
        try:
            self._purge() #Delete old items, so we're assured of a new one
            session = self.entriesDict[bytes(sessionID)]


            if session.valid():
                return session
            else:
                raise KeyError()
        finally:
            self.lock.release()


    def __setitem__(self, sessionID, session):
        self.lock.acquire()
        try:
            self.entriesDict[bytes(sessionID)] = session
            self.entriesList[self.lastIndex] = (bytes(sessionID), time.time())
            self.lastIndex = (self.lastIndex+1) % len(self.entriesList)

            if self.lastIndex == self.firstIndex:
                del(self.entriesDict[self.entriesList[self.firstIndex][0]])
                self.firstIndex = (self.firstIndex+1) % len(self.entriesList)
        finally:
            self.lock.release()

    def _purge(self):
        pass
