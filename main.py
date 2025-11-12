#!/usr/bin/env python3
"""
CodeAlpha_ProjectName: CodeAlpha_NetworkSniffer / main.py
Basic network sniffer that captures packets, prints summary, and optionally saves to a pcap file.

Notes:
- Requires root/administrator privileges to sniff.
- Works best on Linux/macOS with scapy installed. On Windows, run as Administrator.
- Use responsibly and only on networks you own or have explicit permission to test.

Author: Your Name
"""

import argparse
import datetime
import os
from pathlib import Path
from scapy.all import sniff, Packet, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap
from rich.console import Console
from rich.table import Table

console = Console()

def format_proto(pkt: Packet) -> str:
    if IP in pkt:
        proto = pkt[IP].proto
        if proto == 6:
            return "TCP"
        elif proto == 17:
            return "UDP"
        elif proto == 1:
            return "ICMP"
        else:
            return f"IP_PROTO_{proto}"
    if IPv6 in pkt:
        # Basic map for IPv6 next header numbers
        nh = pkt[IPv6].nh
        return f"IPv6_PROTO_{nh}"
    return pkt.__class__.__name__

def extract_fields(pkt: Packet) -> dict:
    ts = datetime.datetime.fromtimestamp(pkt.time).isoformat(sep=' ', timespec='seconds')
    src = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else "N/A")
    dst = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else "N/A")
    proto = format_proto(pkt)
    sport = dst_port = None

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        sport, dport = None, None

    payload = None
    if Raw in pkt:
        raw_bytes = bytes(pkt[Raw].load)
        # Show printable portion, truncate to 120 chars
        try:
            payload = raw_bytes.decode('utf-8', errors='replace')
        except Exception:
            payload = repr(raw_bytes)
        if len(payload) > 120:
            payload = payload[:120] + '...[truncated]'

    return {
        "time": ts,
        "src": src,
        "dst": dst,
        "proto": proto,
        "sport": sport,
        "dport": dport,
        "payload": payload
    }

def print_packet(pkt_summary: dict, index:int=None):
    table = Table(show_header=False, box=None, padding=(0,1))
    if index is not None:
        table.add_row("[bold]#[/bold]", str(index))
    table.add_row("[bold]Time[/bold]", pkt_summary["time"])
    table.add_row("[bold]Src[/bold]", pkt_summary["src"])
    table.add_row("[bold]Dst[/bold]", pkt_summary["dst"])
    table.add_row("[bold]Proto[/bold]", pkt_summary["proto"])
    if pkt_summary["sport"] is not None:
        table.add_row("[bold]SrcPort[/bold]", str(pkt_summary["sport"]))
    if pkt_summary["dport"] is not None:
        table.add_row("[bold]DstPort[/bold]", str(pkt_summary["dport"]))
    if pkt_summary["payload"]:
        table.add_row("[bold]Payload[/bold]", pkt_summary["payload"])
    console.print(table)
    console.rule()

class Sniffer:
    def __init__(self, iface=None, count=0, bpf_filter=None, save=None):
        self.iface = iface
        self.count = count  # 0 = infinite until ctrl-c
        self.filter = bpf_filter
        self.save = Path(save) if save else None
        self.captured = []  # store scapy packets if saving or for analysis
        self.index = 0

    def _handle(self, pkt):
        self.index += 1
        summary = extract_fields(pkt)
        print_packet(summary, self.index)
        if self.save is not None:
            self.captured.append(pkt)

    def run(self):
        console.print(f"[yellow]Starting sniffer[/yellow] on iface=[bold]{self.iface}[/bold] filter=[bold]{self.filter}[/bold] count=[bold]{self.count or 'infinite'}[/bold]")
        try:
            sniff(iface=self.iface, prn=self._handle, store=False if self.save is None else True,
                  count=self.count, filter=self.filter)
        except PermissionError:
            console.print("[red]Permission denied:[/red] you must run as root/Administrator to sniff network interfaces.")
            return
        except Exception as e:
            console.print(f"[red]Sniffer error:[/red] {e}")
            return
        finally:
            if self.save and self.captured:
                pcap_path = self.save
                # create parent dir if needed
                pcap_path.parent.mkdir(parents=True, exist_ok=True)
                wrpcap(str(pcap_path), self.captured)
                console.print(f"[green]Saved {len(self.captured)} packets to[/green] {pcap_path}")

def parse_args():
    p = argparse.ArgumentParser(description="CodeAlpha Network Sniffer (Task 1)")
    p.add_argument("-i", "--iface", help="Network interface to capture on (e.g., eth0, wlan0). If omitted, scapy chooses default.", default=None)
    p.add_argument("-c", "--count", help="Number of packets to capture (0 = infinite until Ctrl-C).", type=int, default=0)
    p.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp', 'port 80', 'udp and host 10.0.0.5')", default=None)
    p.add_argument("-s", "--save", help="Save captured packets to PCAP file (e.g., captures/out.pcap)", default=None)
    return p.parse_args()

def main():
    args = parse_args()
    sn = Sniffer(iface=args.iface, count=args.count, bpf_filter=args.filter, save=args.save)
    sn.run()

if __name__ == "__main__":
    main()
