try:
    from time import ticks_diff
except ImportError:  # CPython, for tests

    def ticks_diff(a, b):
        return a - b


# Scanners end each code with CR and/or LF. Any bytes still waiting with no
# terminator after this long are treated as a complete code, for scanners
# configured without a suffix. A code arrives in one burst (~15 ms for an
# EAN-13 at 9600 baud), so this only fires once the scanner has gone quiet.
IDLE_FLUSH_MS = 200

# Longest code we'll buffer before giving up on finding a terminator. Keeps a
# noisy or misconfigured line from growing the buffer without bound.
MAX_LINE_BYTES = 512


class LineBuffer:
    """Reassembles UART bytes into one entry per scanned code.

    A UART read returns whatever has arrived since the last read: part of a
    code, or several codes run together if the main loop was busy (e.g. in
    an HTTP POST) while they arrived. This splits on CR/LF so each scan is
    handled on its own.
    """

    def __init__(self, idle_flush_ms=IDLE_FLUSH_MS, max_line_bytes=MAX_LINE_BYTES):
        self.idle_flush_ms = idle_flush_ms
        self.max_line_bytes = max_line_bytes
        self._pending = b""
        self._last_byte_ms = 0

    def feed(self, data, now_ms):
        """Add bytes read at `now_ms`; return the complete lines (bytes) they finish."""
        if not data:
            return []
        self._last_byte_ms = now_ms
        self._pending += data.replace(b"\r", b"\n")
        *lines, self._pending = self._pending.split(b"\n")
        if len(self._pending) >= self.max_line_bytes:
            lines.append(self._pending)
            self._pending = b""
        return [line for line in lines if line]

    def flush_idle(self, now_ms):
        """Return the unterminated pending bytes once the line has been quiet long enough."""
        if not self._pending:
            return None
        if ticks_diff(now_ms, self._last_byte_ms) < self.idle_flush_ms:
            return None
        line, self._pending = self._pending, b""
        return line
