#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""python -m cveScanner 入口，委派給 scanCve.py 執行。"""

import sys
from pathlib import Path

_PYTHON_DIR = Path(__file__).parent.parent
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from scanCve import main

if __name__ == "__main__":
    main()
