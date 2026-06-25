#!/usr/bin/env python3
import sys
from pathlib import Path
# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent.usb_monitor as um

class DummyUSBMonitor(um.USBMonitor):
    def start(self):
        import logging
        logging.getLogger(__name__).info("Dummy USBMonitor started (no-ops)")
    def stop(self):
        pass


def create_dummy(db, on_event=None):
    return DummyUSBMonitor(db, on_event)

# Monkeypatch factory
um.create_usb_monitor = create_dummy

from agent.main import USBDLPAgent

if __name__ == '__main__':
    agent = USBDLPAgent()
    agent.start()
