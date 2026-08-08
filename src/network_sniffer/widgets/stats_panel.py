from __future__ import annotations

from collections import Counter

from textual.widgets import Static


class StatsPanel(Static):
    def __init__(self) -> None:
        super().__init__("")
        self.proto_counts: Counter[str] = Counter()
        self.total_packets = 0
        self.total_bytes = 0

    def record(self, proto: str, length: int) -> None:
        self.proto_counts[proto] += 1
        self.total_packets += 1
        self.total_bytes += length
        self._refresh_content()

    def reset(self) -> None:
        self.proto_counts.clear()
        self.total_packets = 0
        self.total_bytes = 0
        self._refresh_content()

    def _refresh_content(self) -> None:
        top = self.proto_counts.most_common(8)
        parts = [f"pkts: {self.total_packets}", f"bytes: {self.total_bytes}"]
        parts += [f"{proto}: {count}" for proto, count in top]
        self.update(" | ".join(parts))
