DEBUG = 10
INFO = 20
WARNING = 30
ERROR = 40
CRITICAL = 50

_LEVEL_NAMES = {
    DEBUG: "DEBUG",
    INFO: "INFO",
    WARNING: "WARNING",
    ERROR: "ERROR",
    CRITICAL: "CRITICAL",
}


class Logger:
    def __init__(self, name):
        self.name = name

    def _log(self, level, msg):
        print(_LEVEL_NAMES[level] + ":" + self.name + ":" + msg)

    def debug(self, msg):
        self._log(DEBUG, msg)

    def info(self, msg):
        self._log(INFO, msg)

    def warning(self, msg):
        self._log(WARNING, msg)

    def error(self, msg):
        self._log(ERROR, msg)

    def critical(self, msg):
        self._log(CRITICAL, msg)


_loggers = {}


def getLogger(name="root"):
    if name not in _loggers:
        _loggers[name] = Logger(name)
    return _loggers[name]
