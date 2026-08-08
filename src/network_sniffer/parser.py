"""Turn a raw Scapy packet into structures the UI can render.

Two outputs per packet:
- a PacketSummary (one row in the live table)
- a nested layer tree (fields for every layer, for the detail pane)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from scapy.packet import Packet


@dataclass
class PacketSummary:
    index: int
    timestamp: float
    src: str
    dst: str
    proto: str
    sport: str
    dport: str
    length: int
    info: str
    raw: Packet = field(repr=False)

    @property
    def source(self) -> str:
        return f"{self.src}:{self.sport}" if self.sport != "-" else self.src

    @property
    def destination(self) -> str:
        return f"{self.dst}:{self.dport}" if self.dport != "-" else self.dst


def _addr_pair(pkt: Packet) -> tuple[str, str]:
    if pkt.haslayer("IP"):
        ip = pkt["IP"]
        return ip.src, ip.dst
    if pkt.haslayer("IPv6"):
        ip6 = pkt["IPv6"]
        return ip6.src, ip6.dst
    if pkt.haslayer("ARP"):
        arp = pkt["ARP"]
        return arp.psrc, arp.pdst
    if pkt.haslayer("Ether"):
        eth = pkt["Ether"]
        return eth.src, eth.dst
    return "-", "-"


def _ports(pkt: Packet) -> tuple[str, str]:
    if pkt.haslayer("TCP"):
        return str(pkt["TCP"].sport), str(pkt["TCP"].dport)
    if pkt.haslayer("UDP"):
        return str(pkt["UDP"].sport), str(pkt["UDP"].dport)
    return "-", "-"


def _top_proto(pkt: Packet) -> str:
    for layer_name in ("TCP", "UDP", "ICMP", "ICMPv6", "ARP", "DNS", "IPv6", "IP"):
        if pkt.haslayer(layer_name):
            return layer_name
    return pkt.lastlayer().name


def summarize(pkt: Packet, index: int) -> PacketSummary:
    src, dst = _addr_pair(pkt)
    sport, dport = _ports(pkt)
    return PacketSummary(
        index=index,
        timestamp=getattr(pkt, "time", time.time()),
        src=src,
        dst=dst,
        proto=_top_proto(pkt),
        sport=sport,
        dport=dport,
        length=len(pkt),
        info=pkt.summary(),
        raw=pkt,
    )


def layer_tree(pkt: Packet) -> list[tuple[str, list[tuple[str, str]]]]:
    """Every layer, every field, as (layer_name, [(field, value), ...])."""
    layers: list[tuple[str, list[tuple[str, str]]]] = []
    current = pkt
    while current is not None:
        fields: list[tuple[str, str]] = []
        for f in current.fields_desc:
            try:
                value = current.getfieldval(f.name)
            except Exception:
                continue
            fields.append((f.name, repr(value)))
        layers.append((current.name, fields))
        current = current.payload if current.payload else None
        if current is not None and current.name == "NoPayload":
            break
    return layers
