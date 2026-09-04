class ResetCalled(Exception):
    pass


def reset():
    raise ResetCalled("machine.reset() called")


class Pin:
    IN = 0
    OUT = 1

    def __init__(self, id, mode=-1, pull=-1):
        self.id = id


class UART:
    def __init__(self, id, baudrate=9600, tx=None, rx=None):
        self.id = id
        self._buffer = b""

    def init(self, bits=8, parity=None, stop=1):
        pass

    def any(self):
        return len(self._buffer) > 0

    def read(self):
        data = self._buffer
        self._buffer = b""
        return data
