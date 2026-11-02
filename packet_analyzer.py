import argparse
from collections import Counter
from itertools import islice
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP
from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import PcapReader


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error

    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def analyze_packet(packet: Packet, packet_number: int) -> str | None:
    if IP not in packet:
        return None

    ip_packet = packet[IP]
    if TCP in packet:
        protocol = "TCP"
        transport = packet[TCP]
        details = f"Source Port: {transport.sport}, Destination Port: {transport.dport}"
    elif UDP in packet:
        protocol = "UDP"
        transport = packet[UDP]
        details = f"Source Port: {transport.sport}, Destination Port: {transport.dport}"
    elif ICMP in packet:
        protocol = "ICMP"
        details = f"ICMP Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
    else:
        protocol = "Other"
        details = f"IP Protocol Number: {ip_packet.proto}"

    print("\n" + "=" * 55)
    print(f"Packet Number: {packet_number}")
    print(f"Time: {packet.time}")
    print(f"Source IP: {ip_packet.src}")
    print(f"Destination IP: {ip_packet.dst}")
    print(f"Protocol: {protocol}")
    print(f"Packet Size: {len(packet)} bytes")
    print(f"Details: {details}")
    print("=" * 55)
    return protocol


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read IP packet metadata from a PCAP or PCAPNG capture file."
    )
    parser.add_argument("capture_file", type=Path, help="path to a .pcap or .pcapng file")
    parser.add_argument(
        "--limit",
        type=positive_integer,
        help="analyze at most this many packets from the capture",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.capture_file.is_file():
        parser.error(f"capture file does not exist or is not a file: {args.capture_file}")

    protocol_counts: Counter[str] = Counter()
    packets_read = 0

    print("\n====================================")
    print("      NETWORK PACKET ANALYZER")
    print("====================================")
    print(f"Capture file: {args.capture_file}")

    try:
        with PcapReader(str(args.capture_file)) as capture:
            packets = capture if args.limit is None else islice(capture, args.limit)
            for packet in packets:
                packets_read += 1
                protocol = analyze_packet(packet, packets_read)
                if protocol is not None:
                    protocol_counts[protocol] += 1
    except (OSError, EOFError, Scapy_Exception) as error:
        parser.error(f"could not read capture file '{args.capture_file}': {error}")

    print("\nCapture analysis completed.")
    print(f"Packets read: {packets_read}")
    print(f"IP packets analyzed: {sum(protocol_counts.values())}")
    if protocol_counts:
        print("Protocol totals:")
        for protocol, total in sorted(protocol_counts.items()):
            print(f"  {protocol}: {total}")
    else:
        print("No IPv4 packets found in the selected capture packets.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
