"""
agent/main.py
---------------
Agent Entry Point / Orchestrator.

This module wires together every component of the Secure USB DLP Phase 1
pipeline into a single running process:

    USBMonitor --(insertion)--> FileMonitor --(file event)--> Scanner
        --> RiskEngine --> PolicyEngine --> AlertManager --> Database

Responsibilities:
    1. Initialize the database (creates usb_dlp.db / applies schema.sql
       on first run).
    2. Start the platform-appropriate USBMonitor (Linux: pyudev,
       Windows: psutil polling).
    3. On USB insertion, attach a FileMonitor (watchdog) to the new
       mount path and start a fresh RiskEngine "session" (for the
       multiple-files-in-session scoring rule).
    4. On every relevant file activity (CREATE/COPY/MODIFY), run the
       Sensitive Data Detection Engine, score the result, evaluate the
       Policy Engine, and raise alerts as needed.
    5. On USB removal, stop the associated FileMonitor and reset the
       RiskEngine session.
    6. Run until interrupted (Ctrl+C / SIGTERM), shutting down cleanly.

Run with:
    python -m agent.main
or via the provided run_agent.sh script.
"""

from __future__ import annotations

import signal
import sys
import threading
import time
from typing import Dict, Optional

from config.settings import settings
from database.db import DatabaseManager
from agent.usb_monitor import create_usb_monitor, USBMonitor
from agent.file_monitor import FileMonitor
from agent.scanner import SensitiveDataScanner
from agent.risk_engine import RiskEngine
from agent.policy_engine import PolicyEngine, DECISION_BLOCK
from agent.alert_manager import AlertManager
from agent.logger import get_logger

logger = get_logger(__name__)

# Actions that should trigger the content-scanning pipeline. DELETE/RENAME
# are logged as file_events (audit trail) but cannot be content-scanned
# (the file's prior content is gone or the path simply changed).
SCANNABLE_ACTIONS = {"CREATE", "COPY", "MODIFY"}


class USBDLPAgent:
    """
    Top-level orchestrator class tying together every Phase 1 component.

    Maintains a registry of active FileMonitor instances keyed by mount
    path, so multiple USB devices can be monitored concurrently and torn
    down independently when removed.
    """

    def __init__(self) -> None:
        logger.info("Initializing %s v%s (%s)", settings.app_name, settings.app_version, settings.app_env)
        self.db = DatabaseManager()
        self.scanner = SensitiveDataScanner()
        self.policy_engine = PolicyEngine()
        self.alert_manager = AlertManager(self.db)

        # One RiskEngine per active mount path, so the "multiple files in
        # session" rule is scoped per-device rather than globally shared.
        self._risk_engines: Dict[str, RiskEngine] = {}
        self._file_monitors: Dict[str, FileMonitor] = {}
        self._lock = threading.Lock()

        self.usb_monitor: USBMonitor = create_usb_monitor(self.db, on_event=self._on_usb_event)
        self._shutdown_event = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start USB monitoring and block until shutdown is requested."""
        self.usb_monitor.start()
        logger.info("USB DLP Agent is running. Press Ctrl+C to stop.")

        self._install_signal_handlers()
        try:
            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(timeout=1)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        """Gracefully stop all USB and file monitors."""
        logger.info("Shutting down USB DLP Agent...")
        self.usb_monitor.stop()
        with self._lock:
            for mount_path, monitor in list(self._file_monitors.items()):
                monitor.stop()
            self._file_monitors.clear()
            self._risk_engines.clear()
        logger.info("Shutdown complete.")

    def _install_signal_handlers(self) -> None:
        def _handler(signum, frame):  # noqa: ANN001
            logger.info("Received signal %s, initiating shutdown...", signum)
            self._shutdown_event.set()

        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except (ValueError, AttributeError):
            # Signal handling may be restricted in some environments
            # (e.g. non-main thread, certain Windows contexts); the
            # agent still works, just without graceful Ctrl+C handling.
            logger.debug("Could not install signal handlers in this environment.")

    # ------------------------------------------------------------------
    # USB device callbacks
    # ------------------------------------------------------------------
    def _on_usb_event(self, event_type: str, device_info: dict) -> None:
        """Callback invoked by USBMonitor on every INSERTED/REMOVED event."""
        mount_path = device_info.get("mount_path")

        if event_type == "INSERTED":
            logger.info("USB device inserted: %s at %s", device_info.get("device_name"), mount_path)
            if not mount_path:
                logger.warning("No mount path resolved for inserted device; file monitoring skipped.")
                return
            self._start_file_monitor(mount_path)

        elif event_type == "REMOVED":
            logger.info("USB device removed: %s", device_info.get("device_name"))
            if mount_path:
                self._stop_file_monitor(mount_path)

    def _start_file_monitor(self, mount_path: str) -> None:
        with self._lock:
            if mount_path in self._file_monitors:
                logger.debug("FileMonitor already active for %s", mount_path)
                return

            usb_event_row = self.db.get_latest_usb_event_for_mount(mount_path)
            usb_event_id = usb_event_row["id"] if usb_event_row else None

            risk_engine = RiskEngine()
            self._risk_engines[mount_path] = risk_engine

            monitor = FileMonitor(
                db=self.db,
                mount_path=mount_path,
                usb_event_id=usb_event_id,
                on_activity=self._make_activity_callback(mount_path),
            )
            monitor.start()
            self._file_monitors[mount_path] = monitor

    def _stop_file_monitor(self, mount_path: str) -> None:
        with self._lock:
            monitor = self._file_monitors.pop(mount_path, None)
            risk_engine = self._risk_engines.pop(mount_path, None)
            if monitor:
                monitor.stop()
            if risk_engine:
                risk_engine.reset_session()

    # ------------------------------------------------------------------
    # File activity pipeline
    # ------------------------------------------------------------------
    def _make_activity_callback(self, mount_path: str):
        """
        Build a closure capturing `mount_path` so the FileMonitor's
        generic callback signature can look up the correct per-device
        RiskEngine instance for the multiple-files rule.
        """

        def _callback(action: str, file_path: str, file_size_bytes: int, file_event_id: Optional[int]) -> None:
            self._process_file_activity(mount_path, action, file_path, file_size_bytes, file_event_id)

        return _callback

    def _process_file_activity(
        self,
        mount_path: str,
        action: str,
        file_path: str,
        file_size_bytes: int,
        file_event_id: Optional[int],
    ) -> None:
        """
        Run the detection -> scoring -> policy -> alert pipeline for a
        single file activity event. Only CREATE/COPY/MODIFY actions are
        content-scanned; DELETE/RENAME are recorded as audit trail only.
        """
        if action not in SCANNABLE_ACTIONS:
            return

        try:
            import getpass
            os_user = getpass.getuser()

            scan_result = self.scanner.scan_file(file_path)

            with self._lock:
                risk_engine = self._risk_engines.get(mount_path)
            if risk_engine is None:
                # Device may have been removed mid-scan; create a
                # throwaway engine so scoring can still complete safely.
                risk_engine = RiskEngine()

            assessment = risk_engine.score(scan_result, file_size_bytes)
            decision = self.policy_engine.evaluate(assessment)

            risk_log_id = self.db.insert_risk_log(
                file_event_id=file_event_id,
                file_name=self._basename(file_path),
                file_path=file_path,
                sensitivity=assessment.sensitivity,
                risk_score=assessment.risk_score,
                matched_rules=assessment.matched_rules,
                match_counts=assessment.match_counts,
                decision=decision.decision,
                os_user=os_user,
            )

            self.alert_manager.raise_alerts(
                assessment=assessment,
                decision=decision,
                file_name=self._basename(file_path),
                file_path=file_path,
                os_user=os_user,
                risk_log_id=risk_log_id,
            )

            if decision.decision == DECISION_BLOCK:
                logger.warning(
                    "BLOCK decision for %s (score=%d). Note: Phase 1 logs/alerts "
                    "on block decisions; physical write-blocking requires an OS-level "
                    "filter driver and is out of scope for this phase.",
                    file_path, assessment.risk_score,
                )

        except Exception:
            logger.exception("Error processing file activity for %s", file_path)

    @staticmethod
    def _basename(file_path: str) -> str:
        import os
        return os.path.basename(file_path)


def main() -> None:
    """Process entry point."""
    agent = USBDLPAgent()
    agent.start()


if __name__ == "__main__":
    sys.exit(main() or 0)
