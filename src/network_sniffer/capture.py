"""Background packet capture.

Uses Scapy's AsyncSniffer rather than hand-rolling a thread around
sniff(). AsyncSniffer.stop() wakes up the internal select() loop via a
control pipe immediately, even with no traffic on the interface. A
manual `sniff(..., stop_filter=...)` thread only re-checks the stop
condition once a packet arrives, so "Stop" would silently do nothing
on a quiet interface until traffic showed up.
"""

from __future__ import annotations

import queue

from scapy.all import conf, get_if_list
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer


class CaptureManager:
    def __init__(self) -> None:
        self.packet_queue: queue.Queue[Packet] = queue.Queue()
        self._sniffer: AsyncSniffer | None = None

    @staticmethod
    def list_interfaces() -> list[str]:
        try:
            return get_if_list()
        except Exception:
            return [conf.iface]

    @property
    def running(self) -> bool:
        # AsyncSniffer sets its own `running = True` before it opens any
        # socket or compiles a filter, and never resets it if that setup
        # raises. A stored exception means the thread is dead regardless
        # of what the raw flag says.
        if self._sniffer is None or self._sniffer.exception is not None:
            return False
        return self._sniffer.running

    @property
    def error(self) -> str | None:
        if self._sniffer is not None and self._sniffer.exception is not None:
            return str(self._sniffer.exception)
        return None

    def start(self, interface: str, bpf_filter: str) -> None:
        if self.running:
            return

        def on_packet(pkt: Packet) -> None:
            self.packet_queue.put(pkt)

        self._sniffer = AsyncSniffer(
            iface=interface or None,
            filter=bpf_filter or None,
            prn=on_packet,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is None:
            return
        try:
            if self._sniffer.running and self._sniffer.exception is None:
                self._sniffer.stop(join=False)
        except Exception:
            # Any exception here is already captured in self._sniffer.exception
            # and surfaced through the `error` property; never let it propagate
            # into a UI event handler or app shutdown.
            pass
