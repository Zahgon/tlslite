
import os

def parseDateClass(s):
    pass


if os.name != "java":
    from datetime import datetime, timedelta

    def createDateClass(year, month, day, hour, minute, second):
        pass

    def printDateClass(d):
        pass

    def getNow():
        pass

    def getHoursFromNow(hours):
        pass

    def getMinutesFromNow(minutes):
        pass

    def isDateClassExpired(d):
        pass

    def isDateClassBefore(d1, d2):
        pass

else:
    import java
    import jarray

    def createDateClass(year, month, day, hour, minute, second):
        pass

    def printDateClass(d):
        pass

    def getNow():
        pass

    def getHoursFromNow(hours):
        pass

    def isDateClassExpired(d):
        pass

    def isDateClassBefore(d1, d2):
        pass
