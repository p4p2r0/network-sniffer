from __future__ import annotations

from datetime import datetime

from textual.widgets import DataTable

from network_sniffer.parser import PacketSummary

MAX_ROWS = 5000


class PacketTable(DataTable):
    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        # Auto-sized columns: never truncates regardless of terminal width,
        # unlike a fixed width which crops a header like "Proto" down to
        # "Pr" on a narrower terminal.
        self.add_columns("Time", "Source", "Destination", "Proto", "Length")
        self._rows: dict[str, PacketSummary] = {}

    def add_packet(self, summary: PacketSummary) -> None:
        row_key = str(summary.index)
        self._rows[row_key] = summary
        ts = datetime.fromtimestamp(summary.timestamp).strftime("%H:%M:%S")
        self.add_row(
            ts,
            summary.source,
            summary.destination,
            summary.proto,
            str(summary.length),
            key=row_key,
        )
        if len(self._rows) > MAX_ROWS:
            oldest_key = next(iter(self._rows))
            self.remove_row(oldest_key)
            del self._rows[oldest_key]
        self.move_cursor(row=self.row_count - 1)

    def get_selected(self) -> PacketSummary | None:
        if self.cursor_row is None:
            return None
        try:
            row_key, _ = self.coordinate_to_cell_key((self.cursor_row, 0))
        except Exception:
            return None
        return self._rows.get(row_key.value)

    def clear_packets(self) -> None:
        self.clear()
        self._rows.clear()
