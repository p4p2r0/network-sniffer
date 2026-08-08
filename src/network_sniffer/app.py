from __future__ import annotations

import logging
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import Button, Footer, Select, Static, Switch

from network_sniffer.capture import CaptureManager
from network_sniffer.parser import summarize
from network_sniffer.pcap_writer import TogglablePcapWriter
from network_sniffer.privileges import has_capture_privileges, privilege_error_message
from network_sniffer.widgets.control_bar import ControlBar
from network_sniffer.widgets.detail_tree import DetailTree
from network_sniffer.widgets.packet_table import PacketTable
from network_sniffer.widgets.stats_panel import StatsPanel

QUEUE_POLL_INTERVAL = 0.1
MAX_PACKETS_PER_TICK = 200


def _silence_scapy_logging() -> None:
    """Stop Scapy writing to the terminal.

    Scapy logs warnings straight to stderr. In a full-screen TUI that
    paints over the interface and stays there until the next redraw, so
    every Scapy logger is muted and detached from its stream handlers.
    """
    for name in ("scapy", "scapy.runtime", "scapy.loading", "scapy.interactive"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.CRITICAL + 1)
        logger.propagate = False
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())

# A registered Theme sets Textual's actual design tokens ($primary, $accent,
# $surface, $foreground, ...) so every built-in widget internal — Select's
# SelectCurrent, Switch's slider, Header, Footer — picks up matching colors
# automatically. Overriding individual widgets' CSS piecemeal misses their
# nested sub-widgets, which is what caused the invisible Select text and
# stray blue border before.
DARK_THEME = Theme(
    name="network-sniffer-dark",
    primary="#d9a566",
    secondary="#8a8a8a",
    accent="#d9a566",
    warning="#d9a566",
    error="#c2453b",
    success="#3d9a48",
    foreground="#e6e6e6",
    background="#121212",
    surface="#1a1a1a",
    panel="#1c1c1c",
    dark=True,
)


class PrivilegeErrorScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Static(privilege_error_message(), id="priv_error")
        yield Footer()

    def on_key(self, event) -> None:
        self.app.exit()


class NetworkSnifferApp(App):
    TITLE = "network-sniffer"

    CSS = """
    Screen { background: $background; color: $foreground; }
    Footer { background: $surface; }

    /* A terminal can't render a bigger font, so the title gets presence
       from surrounding space alone — no rule beneath it, since the
       control bar below already has its own border. */
    #app_title {
        height: 3;
        content-align: left middle;
        background: $surface;
        color: $primary;
        text-style: bold;
        padding: 0 2;
    }

    /* height must be 4, not 3: the bottom border is drawn inside the box,
       so height 3 leaves only 2 content rows while Select/Input/Switch/
       Button each need 3 (they use `border: tall`), clipping their
       bottom row. 3 content rows + 1 border row = 4. */
    ControlBar {
        height: 4;
        align: left middle;
        background: $surface;
        border-bottom: solid $panel-lighten-2;
        padding: 0 1;
    }
    ControlBar .field-label {
        width: auto;
        height: 1;
        padding: 0 1 0 0;
        color: $text-muted;
        text-style: bold;
    }
    ControlBar Select { width: 16; margin-right: 2; }
    ControlBar Input { width: 1fr; min-width: 12; margin-right: 2; }
    ControlBar Switch { width: 8; margin-right: 2; }
    ControlBar Button { width: 12; margin-left: 1; }

    /* Button uses `color: auto` internally, which recomputes black/white
       text based on background lightness and visibly flickers while
       pressed. Set text color explicitly so it never recomputes. */
    ControlBar Button, ControlBar Button.-success, ControlBar Button.-error {
        color: #ffffff;
        text-style: bold;
    }

    #error_banner {
        height: 1;
        background: $error;
        color: #ffffff;
        text-style: bold;
        padding: 0 1;
        display: none;
    }

    #main_split { height: 1fr; }

    PacketTable { width: 3fr; border: solid $panel-lighten-2; }
    PacketTable > .datatable--header { color: $primary; text-style: bold; }

    DetailTree { width: 2fr; border: solid $panel-lighten-2; padding: 0 1; }

    StatsPanel {
        height: 1;
        background: $surface;
        color: $text-muted;
        padding: 0 1;
        border-top: solid $panel-lighten-2;
    }

    #priv_error { padding: 2; color: $error; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "clear", "Clear"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.capture = CaptureManager()
        self.pcap_writer = TogglablePcapWriter(Path.cwd() / "captures")
        self._packet_index = 0
        self._shown_error: str | None = None

    def compose(self) -> ComposeResult:
        yield Static("network-sniffer", id="app_title")
        yield ControlBar(self.capture.list_interfaces())
        yield Static("", id="error_banner")
        with Horizontal(id="main_split"):
            yield PacketTable()
            yield DetailTree()
        yield StatsPanel()
        yield Footer()

    def on_mount(self) -> None:
        _silence_scapy_logging()
        self.register_theme(DARK_THEME)
        self.theme = DARK_THEME.name
        if not has_capture_privileges():
            self.push_screen(PrivilegeErrorScreen())
            return
        self.set_interval(QUEUE_POLL_INTERVAL, self._drain_queue)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "start_stop_btn":
            return
        if self.capture.running:
            self.capture.stop()
            event.button.label = "Start"
            event.button.variant = "success"
        else:
            iface_select = self.query_one("#iface_select", Select)
            filter_input = self.query_one("#filter_input")
            self.capture.start(str(iface_select.value), filter_input.value)
            event.button.label = "Stop"
            event.button.variant = "error"

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id != "pcap_switch":
            return
        if event.value:
            self.pcap_writer.enable()
        else:
            self.pcap_writer.disable()

    def on_data_table_row_highlighted(self, event) -> None:
        table = self.query_one(PacketTable)
        self.query_one(DetailTree).show_packet(table.get_selected())

    def action_clear(self) -> None:
        self.query_one(PacketTable).clear_packets()
        self.query_one(DetailTree).show_packet(None)
        self.query_one(StatsPanel).reset()

    def _drain_queue(self) -> None:
        self._check_capture_error()
        table = self.query_one(PacketTable)
        stats = self.query_one(StatsPanel)
        drained = 0
        while drained < MAX_PACKETS_PER_TICK:
            try:
                pkt = self.capture.packet_queue.get_nowait()
            except Exception:
                break
            self._packet_index += 1
            summary = summarize(pkt, self._packet_index)
            table.add_packet(summary)
            stats.record(summary.proto, summary.length)
            self.pcap_writer.write(pkt)
            drained += 1

    def _check_capture_error(self) -> None:
        error = self.capture.error
        banner = self.query_one("#error_banner", Static)
        if error is None:
            if self._shown_error is not None:
                self._shown_error = None
                banner.display = False
                banner.update("")
            return
        if error == self._shown_error:
            return
        self._shown_error = error
        banner.update(f"Capture error: {error}")
        banner.display = True
        button = self.query_one("#start_stop_btn", Button)
        button.label = "Start"
        button.variant = "success"

    def on_unmount(self) -> None:
        self.capture.stop()
        self.pcap_writer.disable()
