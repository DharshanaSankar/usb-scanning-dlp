"""
Agent package for the Secure USB DLP System.

Contains the background monitoring agent components:
    - usb_monitor.py    : USB insertion/removal detection (Linux/Windows)
    - file_monitor.py   : File activity monitoring on mounted USB volumes
    - scanner.py         : Sensitive Data Detection Engine (regex-based)
    - risk_engine.py     : Rule-based Risk Scoring Engine
    - policy_engine.py   : Allow/Block decision engine
    - alert_manager.py   : Alert generation and persistence
    - logger.py           : Shared logging configuration
    - main.py             : Agent entry point / orchestrator
"""
