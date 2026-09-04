STA_IF = 0


class WLAN:
    def __init__(self, interface):
        self._active = False
        self._connected = False
        self._ssid = None

    def active(self, val=None):
        if val is not None:
            self._active = val
        return self._active

    def isconnected(self):
        return self._connected

    def connect(self, ssid, password=""):
        self._ssid = ssid

    def ifconfig(self):
        return ("192.168.1.100", "255.255.255.0", "192.168.1.1", "8.8.8.8")
