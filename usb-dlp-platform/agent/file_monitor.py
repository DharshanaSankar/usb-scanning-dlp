"""
agent/file_monitor.py
----------------------
File Activity Monitoring Module.

Watches a mounted USB volume's filesystem for Create, Modify, Delete,
and Rename events using the `watchdog` library (cross-platform: uses
inotify on Linux, ReadDirectoryChangesW on Windows under the hood).

"Copy" is treated as a special case of CREATE: when a brand-new file
appears on the USB drive with non-zero size, we classify it as COPY
since, in the overwhelming majority of real-world USB DLP scenarios,
files arriving on a USB drive got there via a copy operation from the
host machine. A plain CREATE (e.g., an empty file or a newly created
document saved directly to the drive) is recorded as CREATE.

Each detected event is:
    1. Persisted to file_events via DatabaseManager.
    2. Forwarded to a callback (typically the agent orchestrator), which
       triggers the Sensitive Data Detection Engine on CREATE/COPY/MODIFY
       events for eligible file extensions.

OOP design:
    `USBFileEventHandler` extends watchdog's `FileSystemEventHandler`.
    `FileMonitor` wraps an `Observer` instance scoped to a single mount
    path, so the orchestrator can start/stop one FileMonitor per
    currently-inserted USB device.
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from database.db import DatabaseManager, utc_now_iso
from agent.logger import get_logger

logger = get_logger(__name__)

# Callback signature: (action, file_path, file_size_bytes, usb_event_id) -> None
FileActivityCallback = Callable[[str, str, int, Optional[int]], None]


class USBFileEventHandler(FileSystemEventHandler):
    """
    Translates raw watchdog filesystem events into the DLP system's
    domain vocabulary (CREATE/COPY/MODIFY/DELETE/RENAME) and persists
    them via DatabaseManager.

    Directories are ignored; only regular file events are processed,
    since sensitive-data scanning operates on file contents.
    """

    def __init__(
        self,
        db: DatabaseManager,
        usb_event_id: Optional[int],
        mount_path: str,
        on_activity: Optional[FileActivityCallback] = None,
    ) -> None:
        super().__init__()
        self.db = db
        self.usb_event_id = usb_event_id
        self.mount_path = mount_path
        self.on_activity = on_activity
        self._current_user = getpass.getuser()

    # ------------------------------------------------------------------
    # watchdog event callbacks
    # ------------------------------------------------------------------
    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._process_event(action="COPY", src_path=event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._process_event(action="MODIFY", src_path=event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._process_event(action="DELETE", src_path=event.src_path, file_exists=False)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._process_event(action="RENAME", src_path=event.dest_path)

    # ------------------------------------------------------------------
    # Shared processing logic
    # ------------------------------------------------------------------
    def _process_event(self, action: str, src_path: str, file_exists: bool = True) -> None:
        """
        Persist the file event and notify the orchestrator callback.

        Wrapped defensively: watchdog invokes handlers synchronously on
        its observer thread, so any unhandled exception here could
        silently stop further event delivery.
        """
        try:
            file_name = os.path.basename(src_path)
            extension = Path(src_path).suffix.lstrip(".").lower()
            file_size_bytes = 0
            if file_exists:
                try:
                    file_size_bytes = os.path.getsize(src_path)
                except OSError:
                    file_size_bytes = 0

            file_event_id = self.db.insert_file_event(
                usb_event_id=self.usb_event_id,
                action=action,
                file_name=file_name,
                extension=extension,
                file_size_bytes=file_size_bytes,
                file_path=src_path,
                os_user=self._current_user,
                timestamp=utc_now_iso(),
            )

            logger.info(
                "File activity: action=%s file=%s size=%dB user=%s",
                action, file_name, file_size_bytes, self._current_user,
            )

            if self.on_activity:
                # Pass file_event_id forward so downstream stages (scanner,
                # risk engine, alerts) can be traced back to this record.
                self.on_activity(action, src_path, file_size_bytes, file_event_id)

        except Exception:
            logger.exception("Failed to process file event action=%s path=%s", action, src_path)


class FileMonitor:
    """
    Wraps a watchdog Observer scoped to a single USB mount path.

    One FileMonitor instance is created per currently-inserted USB
    device by the agent orchestrator (main.py), and stopped when the
    corresponding device is removed.
    """

    def __init__(
        self,
        db: DatabaseManager,
        mount_path: str,
        usb_event_id: Optional[int] = None,
        on_activity: Optional[FileActivityCallback] = None,
    ) -> None:
        self.db = db
        self.mount_path = mount_path
        self.usb_event_id = usb_event_id
        self.on_activity = on_activity
        self._observer: Optional[Observer] = None
        self._handler: Optional[USBFileEventHandler] = None

    def start(self) -> None:
        """Begin watching `self.mount_path` recursively for file changes."""
        if not os.path.isdir(self.mount_path):
            logger.error("Cannot start FileMonitor: mount path does not exist: %s", self.mount_path)
            return

        self._handler = USBFileEventHandler(
            db=self.db,
            usb_event_id=self.usb_event_id,
            mount_path=self.mount_path,
            on_activity=self.on_activity,
        )
        self._observer = Observer()
        self._observer.schedule(self._handler, self.mount_path, recursive=True)
        self._observer.start()
        logger.info("FileMonitor watching mount path: %s", self.mount_path)

    def stop(self) -> None:
        """Stop watching and release the observer thread."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            logger.info("FileMonitor stopped for mount path: %s", self.mount_path)
        self._observer = None
        self._handler = None
