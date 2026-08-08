"""Root/administrator privilege detection.

Raw socket capture requires elevated privileges on every supported OS:
Linux/macOS need root for AF_PACKET/BPF access, Windows needs an
administrator process plus Npcap installed.
"""

from __future__ import annotations

import ctypes
import os
import platform


def has_capture_privileges() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def privilege_error_message() -> str:
    system = platform.system()
    if system == "Windows":
        return (
            "Administrator privileges required.\n\n"
            "Re-launch this terminal as Administrator, and make sure "
            "Npcap is installed (with WinPcap Compatibility Mode enabled)."
        )
    return (
        "Root privileges required.\n\n"
        "Re-run with: sudo network-sniffer\n"
        "(or: sudo uv run network-sniffer)"
    )
