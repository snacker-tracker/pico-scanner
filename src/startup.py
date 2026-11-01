import time

# boot.py imports this module before anything else, so this is the tick count
# at the moment boot.py started running.
BOOT_TICKS = time.ticks_ms()

# The rp2 tick counter restarts on a hardware reset (power-on, machine.reset(),
# watchdog) but keeps counting through a soft reboot (Ctrl-D, mpremote), and
# machine.reset_cause() can't tell a soft reboot apart from the hardware reset
# before it. Firmware init takes well under a second, so a counter already past
# this threshold when boot.py starts means this boot was a soft reboot.
SOFT_REBOOT_THRESHOLD_MS = 5000


def was_soft_reboot():
    return BOOT_TICKS > SOFT_REBOOT_THRESHOLD_MS
