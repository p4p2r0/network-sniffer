"""Toggleable .pcap output.

The underlying PcapWriter is opened lazily, on the first packet rather
than when the toggle is flipped. Scapy determines a pcap file's
link-layer type from the first packet it sees; closing a writer that
never received one makes it print a warning straight to the terminal,
which corrupts a full-screen TUI until the next redraw. Opening lazily
means the file is only ever created when there is a packet to define
the linktype.

Packets are written as they arrive rather than buffered until exit, so
Ctrl+C or a crash still leaves a valid, playable .pcap file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scapy.packet import Packet
from scapy.utils import PcapWriter


class TogglablePcapWriter:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self._writer: PcapWriter | None = None
        self._armed = False
        self.current_path: Path | None = None

    @property
    def enabled(self) -> bool:
        return self._armed

    def enable(self) -> None:
        self._armed = True

    def disable(self) -> None:
        self._armed = False
        if self._writer is not None:
            self._writer.close()
            self._writer = None

    def write(self, pkt: Packet) -> None:
        if not self._armed:
            return
        if self._writer is None:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            self.current_path = self.output_dir / f"capture_{stamp}.pcap"
            self._writer = PcapWriter(str(self.current_path), append=True, sync=True)
        self._writer.write(pkt)
