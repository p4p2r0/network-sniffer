from __future__ import annotations

from textual.containers import Horizontal
from textual.widgets import Button, Input, Label, Select, Switch


class ControlBar(Horizontal):
    def __init__(self, interfaces: list[str]) -> None:
        super().__init__()
        self._interfaces = interfaces

    def compose(self):
        options = [(name, name) for name in self._interfaces] or [("default", "")]
        yield Label("IFACE", classes="field-label")
        yield Select(options, id="iface_select", allow_blank=False, value=options[0][1])
        yield Label("FILTER", classes="field-label")
        yield Input(placeholder="e.g. tcp port 443", id="filter_input")
        yield Label("PCAP", classes="field-label")
        yield Switch(id="pcap_switch", value=False)
        yield Button("Start", id="start_stop_btn", variant="success")
