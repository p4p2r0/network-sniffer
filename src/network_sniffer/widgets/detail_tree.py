from __future__ import annotations

from textual.widgets import Tree

from network_sniffer.parser import PacketSummary, layer_tree

MAX_VALUE_CHARS = 60


class DetailTree(Tree):
    def __init__(self) -> None:
        super().__init__("Packet")
        self.show_root = False

    def show_packet(self, summary: PacketSummary | None) -> None:
        self.clear()
        if summary is None:
            return
        self.root.set_label(f"Packet #{summary.index}")
        for layer_name, fields in layer_tree(summary.raw):
            layer_node = self.root.add(layer_name, expand=True)
            for field_name, value in fields:
                # Payload fields (DNS records, raw loads) can be thousands of
                # characters on one line, forcing horizontal scroll across the
                # whole pane. Truncate for display; the full packet is still
                # written intact to the .pcap.
                if len(value) > MAX_VALUE_CHARS:
                    value = f"{value[:MAX_VALUE_CHARS]}… ({len(value)} chars)"
                layer_node.add_leaf(f"{field_name} = {value}")
