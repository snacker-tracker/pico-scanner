from scan_input import LineBuffer


def test_single_code_with_cr():
    assert LineBuffer().feed(b"4006381333931\r", 0) == [b"4006381333931"]


def test_crlf_and_lf_terminators():
    buf = LineBuffer()
    assert buf.feed(b"036000291452\r\n", 0) == [b"036000291452"]
    assert buf.feed(b"CODE128-TEST-01\n", 10) == [b"CODE128-TEST-01"]


def test_codes_buffered_during_a_post_come_out_separately():
    # Seen on hardware: two scans waiting in the UART while a POST ran were
    # read together and posted as one 26-digit code.
    buf = LineBuffer()
    assert buf.feed(b"1000000000002\r1000000000003\r", 0) == [
        b"1000000000002",
        b"1000000000003",
    ]


def test_code_split_across_reads_is_reassembled():
    buf = LineBuffer()
    assert buf.feed(b"33333", 0) == []
    assert buf.flush_idle(20) is None
    assert buf.feed(b"33333333\r", 30) == [b"3333333333333"]
    assert buf.flush_idle(1000) is None


def test_unterminated_code_flushed_after_idle():
    buf = LineBuffer(idle_flush_ms=200)
    assert buf.feed(b"NOTERMINATOR123", 1000) == []
    assert buf.flush_idle(1199) is None
    assert buf.flush_idle(1200) == b"NOTERMINATOR123"
    assert buf.flush_idle(5000) is None


def test_idle_timer_restarts_on_each_read():
    buf = LineBuffer(idle_flush_ms=200)
    buf.feed(b"ABC", 0)
    buf.feed(b"DEF", 150)
    assert buf.flush_idle(300) is None
    assert buf.flush_idle(350) == b"ABCDEF"


def test_terminated_codes_before_an_unterminated_tail():
    buf = LineBuffer(idle_flush_ms=200)
    assert buf.feed(b"111\r222", 0) == [b"111"]
    assert buf.flush_idle(200) == b"222"


def test_empty_lines_and_empty_reads_are_dropped():
    buf = LineBuffer()
    assert buf.feed(b"\r\n\r", 0) == []
    assert buf.feed(b"", 10) == []
    assert buf.feed(None, 20) == []
    assert buf.flush_idle(10_000) is None


def test_long_code_without_terminator_is_capped():
    buf = LineBuffer(max_line_bytes=8)
    assert buf.feed(b"ABCDEFGHIJ", 0) == [b"ABCDEFGHIJ"]
    assert buf.flush_idle(10_000) is None


def test_long_code_split_across_reads_stays_whole():
    # Seen on hardware: a 300-char code was read in two parts and posted twice.
    buf = LineBuffer()
    assert buf.feed(b"L" * 250, 0) == []
    assert buf.feed(b"L" * 50 + b"\r", 50) == [b"L" * 300]


def test_undecodable_bytes_are_passed_through_for_the_caller():
    assert LineBuffer().feed(b"\xff\xfe\x00garbage\r", 0) == [b"\xff\xfe\x00garbage"]
