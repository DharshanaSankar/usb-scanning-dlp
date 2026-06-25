"""
agent/usb_monitor.py
---------------------
USB Monitoring Module.

Detects USB storage device insertion and removal events in a
cross-platform manner:

    - Linux:   pyudev (subscribes to kernel "block" device uevents)
    - Windows: psutil polling loop (watchdog is used by file_monitor.py
               for filesystem events; OS-level device arrival on Windows
               has no equivalent of udev, so polling disk partitions via
               psutil is the standard, dependency-light approach)

On every insertion/removal, the captured metadata (device name, vendor
ID, product ID, serial number, mount path, timestamp) is persisted via
DatabaseManager.insert_usb_event(), and a callback is invoked so the
agent orchestrator (main.py) can attach a FileMonitor to the new mount
point.

OOP design:
    `USBMonitor` is an abstract base class. `LinuxUSBMonitor` and
    `WindowsUSBMonitor` provide platform-specific implementations.
    `create_usb_monitor()` is a factory function that returns the
    correct implementation for the current OS, so calling code (main.py)
    never needs to branch on `platform.system()` itself.
"""

from __future__ import annotations

import platform
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, Dict, Optional

from config.settings import settings
from database.db import DatabaseManager, utc_now_iso
from agent.logger import get_logger

logger = get_logger(__name__)

# Type alias for the callback invoked when a device is inserted/removed.
# Signature: callback(event_type: str, device_info: dict) -> None
DeviceEventCallback = Callable[[str, Dict[str, Optional[str]]], None]


class USBMonitor(ABC):
    """
    Abstract base class for platform-specific USB monitors.

    Subclasses must implement `start()` and `stop()`. The base class
    provides the shared `_handle_event()` helper that persists the event
    to the database and fires the registered callback.
    """

    def __init__(self, db: DatabaseManager, on_event: Optional[DeviceEventCallback] = None) -> None:
        self.db = db
        self.on_event = on_event
        self._running = False

    @abstractmethod
    def start(self) -> None:
        """Begin monitoring for USB device events (non-blocking; spawns a thread)."""
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """Stop monitoring and release any OS resources."""
        raise NotImplementedError

    def _handle_event(self, event_type: str, device_info: Dict[str, Optional[str]]) -> None:
        """
        Shared logic: persist the event, log it, and notify the callback.

        Wrapped in a broad try/except because this runs inside an OS
        event callback / background thread — an unhandled exception here
        could silently kill the monitoring thread.
        """
        try:
            platform_name = "windows" if settings.is_windows else "linux"
            self.db.insert_usb_event(
                event_type=event_type,
                device_name=device_info.get("device_name"),
                vendor_id=device_info.get("vendor_id"),
                product_id=device_info.get("product_id"),
                serial_number=device_info.get("serial_number"),
                mount_path=device_info.get("mount_path"),
                platform_name=platform_name,
                timestamp=utc_now_iso(),
            )
            if self.on_event:
                self.on_event(event_type, device_info)
        except Exception:
            logger.exception("Failed to handle USB %s event for %s", event_type, device_info)


# =============================================================================
# Linux implementation (pyudev)
# =============================================================================
class LinuxUSBMonitor(USBMonitor):
    """
    Monitors USB block device add/remove events via pyudev on Linux.

    pyudev's MonitorObserver runs its own background thread and invokes
    our callback for every matching uevent, so `start()` simply wires up
    the observer and returns immediately (non-blocking).
    """

    def __init__(self, db: DatabaseManager, on_event: Optional[DeviceEventCallback] = None) -> None:
        super().__init__(db, on_event)
        self._observer = None
        self._context = None
        self._monitor = None
        # Track known mount paths per device so REMOVED events can report
        # the mount path that was last seen for that device's serial number.
        self._known_mounts: Dict[str, str] = {}

    def start(self) -> None:
        try:
            import pyudev  # imported lazily so non-Linux hosts don't require it
        except ImportError:
            logger.error(
                "pyudev is not installed. Install it with 'pip install pyudev' "
                "to enable USB monitoring on Linux."
            )
            raise

        self._context = pyudev.Context()
        self._monitor = pyudev.Monitor.from_netlink(self._context)
        self._monitor.filter_by(subsystem="block")

        self._observer = pyudev.MonitorObserver(
            self._monitor, callback=self._udev_callback, name="usb-dlp-udev-observer"
        )
        self._observer.start()
        self._running = True
        logger.info("LinuxUSBMonitor started (pyudev netlink listener active)")

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
        self._running = False
        logger.info("LinuxUSBMonitor stopped")

    def _udev_callback(self, action: str, device) -> None:  # noqa: ANN001 - pyudev.Device type
        """
        Called by pyudev on every block subsystem uevent. We only care
        about partition-level add/remove events that originate from a
        USB bus, and only those that represent removable storage.
        """
        try:
            if device.get("ID_BUS") != "usb":
                return
            if device.device_type != "partition" and device.get("DEVTYPE") != "partition":
                # Some devices only emit a 'disk' event without a partition;
                # we still try to use it if no partition event is seen.
                if device.device_type != "disk":
                    return

            device_name = device.get("ID_MODEL", "Unknown USB Device")
            vendor_id = device.get("ID_VENDOR_ID", "")
            product_id = device.get("ID_MODEL_ID", "")
            serial_number = device.get("ID_SERIAL_SHORT", device.get("ID_SERIAL", "UNKNOWN"))
            mount_path = self._resolve_mount_path(device)

            device_info = {
                "device_name": device_name,
                "vendor_id": vendor_id,
                "product_id": product_id,
                "serial_number": serial_number,
                "mount_path": mount_path,
            }

            if action == "add":
                if mount_path:
                    self._known_mounts[serial_number] = mount_path
                self._handle_event("INSERTED", device_info)
            elif action == "remove":
                # Mount path is typically gone by the time 'remove' fires;
                # fall back to last-known mount path for this serial.
                if not mount_path:
                    device_info["mount_path"] = self._known_mounts.pop(serial_number, None)
                self._handle_event("REMOVED", device_info)
        except Exception:
            logger.exception("Error processing udev event action=%s", action)

    @staticmethod
    def _resolve_mount_path(device) -> Optional[str]:  # noqa: ANN001
        """
        Attempt to resolve the mount path for a udev device by cross
        referencing /proc/mounts. pyudev does not expose mount points
        directly since mounting is a userspace (not kernel) concept.
        """
        try:
            device_node = device.device_node
            if not device_node:
                return None
            with open("/proc/mounts", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == device_node:
                        return parts[1]
        except Exception:
            logger.debug("Could not resolve mount path for device", exc_info=True)
        return None


# =============================================================================
# Windows implementation (psutil polling)
# =============================================================================
class WindowsUSBMonitor(USBMonitor):
    """
    Monitors removable drive arrival/removal on Windows by polling
    `psutil.disk_partitions()` at a fixed interval and diffing the set
    of removable drive letters between polls.

    Windows has no lightweight, dependency-free equivalent to udev for
    detecting device arrival without WMI/pywin32; polling via psutil
    keeps the dependency footprint aligned with the project's stated
    library list (psutil, watchdog) while remaining fully cross-platform
    in pure Python.
    """

    def __init__(self, db: DatabaseManager, on_event: Optional[DeviceEventCallback] = None) -> None:
        super().__init__(db, on_event)
        self._thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._known_drives: Dict[str, Dict[str, Optional[str]]] = {}

    def start(self) -> None:
        self._stop_flag.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name="usb-dlp-windows-poller", daemon=True
        )
        self._thread.start()
        self._running = True
        logger.info("WindowsUSBMonitor started (psutil polling every %ss)", settings.poll_interval_seconds)

    def stop(self) -> None:
        self._stop_flag.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("WindowsUSBMonitor stopped")

    def _poll_loop(self) -> None:
        import psutil  # imported lazily; only required on Windows

        while not self._stop_flag.is_set():
            try:
                current = self._scan_removable_drives(psutil)
                current_letters = set(current.keys())
                known_letters = set(self._known_drives.keys())

                # New drives -> INSERTED
                for letter in current_letters - known_letters:
                    info = current[letter]
                    self._handle_event("INSERTED", info)

                # Disappeared drives -> REMOVED
                for letter in known_letters - current_letters:
                    info = self._known_drives[letter]
                    self._handle_event("REMOVED", info)

                self._known_drives = current
            except Exception:
                logger.exception("Error during Windows USB poll cycle")

            self._stop_flag.wait(settings.poll_interval_seconds)

    @staticmethod
    def _scan_removable_drives(psutil_module) -> Dict[str, Dict[str, Optional[str]]]:  # noqa: ANN001
        """
        Return a dict keyed by drive letter (e.g. 'E:\\') of removable
        drives currently present, using psutil's partition opts which
        report 'removable' for USB mass storage devices on Windows.
        """
        result: Dict[str, Dict[str, Optional[str]]] = {}
        for part in psutil_module.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            is_removable = "removable" in opts or part.fstype.lower() in {"fat32", "exfat"}
            if not is_removable:
                continue
            try:
                usage = psutil_module.disk_usage(part.mountpoint)
                size_label = f"{usage.total // (1024 * 1024)}MB"
            except Exception:
                size_label = "unknown"

            result[part.device] = {
                "device_name": f"USB Drive ({part.device})",
                "vendor_id": None,
                "product_id": None,
                # psutil has no serial number API; Windows serial requires
                # WMI which is intentionally out of scope for Phase 1's
                # dependency list (pyudev/watchdog/psutil only).
                "serial_number": f"WIN-{part.device.rstrip(':\\\\')}-{size_label}",
                "mount_path": part.mountpoint,
            }
        return result


# =============================================================================
# Factory
# =============================================================================
def create_usb_monitor(db: DatabaseManager, on_event: Optional[DeviceEventCallback] = None) -> USBMonitor:
    """
    Factory function returning the correct USBMonitor implementation for
    the current operating system. Callers (main.py) should use this
    instead of instantiating LinuxUSBMonitor/WindowsUSBMonitor directly.
    """
    system = platform.system().lower()
    if system == "linux":
        return LinuxUSBMonitor(db, on_event)
    elif system == "windows":
        return WindowsUSBMonitor(db, on_event)
    else:
        logger.warning(
            "Unsupported platform '%s' for USB monitoring; falling back to "
            "Windows-style psutil polling as a best-effort implementation.",
            system,
        )
        return WindowsUSBMonitor(db, on_event)
