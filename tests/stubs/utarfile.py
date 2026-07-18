DIRTYPE = b'5'


class TarInfo:
    def __init__(self, name, type=b'0', size=0):
        self.name = name
        self.type = type
        self.size = size


class TarFile:
    def __init__(self, name):
        self.name = name
        self._entries = []

    def __iter__(self):
        return iter(self._entries)

    def extractfile(self, tarinfo):
        return tarinfo._data
