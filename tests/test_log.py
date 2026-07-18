def test_get_logger_returns_same_instance_for_same_name():
    import log
    assert log.getLogger("a") is log.getLogger("a")


def test_get_logger_returns_different_instances_for_different_names():
    import log
    assert log.getLogger("a") is not log.getLogger("b")


def test_log_levels_dont_raise(capsys):
    import log
    logger = log.getLogger("test_log_levels")
    logger.debug("d")
    logger.info("i")
    logger.warning("w")
    logger.error("e")
    logger.critical("c")

    out = capsys.readouterr().out
    assert "DEBUG:test_log_levels:d" in out
    assert "CRITICAL:test_log_levels:c" in out
