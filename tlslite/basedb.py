

try:
    import anydbm
except ImportError:
    import dbm as anydbm
import threading

class BaseDB(object):
    def __init__(self, filename, type):
        self.type = type
        self.filename = filename
        if self.filename:
            self.db = None
        else:
            self.db = {}
        self.lock = threading.Lock()

    def create(self):
        """Create a new on-disk database.

        @raise anydbm.error: If there's a problem creating the database.
        """
        if self.filename:
            self.db = anydbm.open(self.filename, "n") #raises anydbm.error
            self.db["--Reserved--type"] = self.type
            self.db.sync()
        else:
            self.db = {}

    def open(self):
        pass

    def __getitem__(self, username):
        if self.db == None:
            raise AssertionError("DB not open")

        self.lock.acquire()
        try:
            valueStr = self.db[username]
        finally:
            self.lock.release()

        return self._getItem(username, valueStr)

    def __setitem__(self, username, value):
        if self.db == None:
            raise AssertionError("DB not open")

        valueStr = self._setItem(username, value)

        self.lock.acquire()
        try:
            self.db[username] = valueStr
            if self.filename:
                self.db.sync()
        finally:
            self.lock.release()

    def __delitem__(self, username):
        if self.db == None:
            raise AssertionError("DB not open")

        self.lock.acquire()
        try:
            del(self.db[username])
            if self.filename:
                self.db.sync()
        finally:
            self.lock.release()

    def __contains__(self, username):
        """Check if the database contains the specified username.

        @type username: str
        @param username: The username to check for.

        @rtype: bool
        @return: True if the database contains the username, False
        otherwise.

        """
        if self.db == None:
            raise AssertionError("DB not open")

        self.lock.acquire()
        try:
            return self.db.has_key(username)
        finally:
            self.lock.release()

    def check(self, username, param):
        pass

    def keys(self):
        pass
