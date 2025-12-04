#!/usr/bin/env python
# QuarantineManager.pyw - Double-click to open Quarantine GUI
# .pyw extension runs without showing console window

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import and run GUI
from watchDog import open_quarantine_gui

if __name__ == "__main__":
    open_quarantine_gui()
