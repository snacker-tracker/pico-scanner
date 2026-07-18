import sys
import os

# Stubs must come before src so MicroPython-only modules resolve to our fakes
_tests_dir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_tests_dir, 'stubs'))
sys.path.insert(1, os.path.join(_tests_dir, '..', 'src'))
