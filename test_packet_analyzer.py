import argparse
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, wrpcap

import packet_analyzer


class PositiveIntegerTests(unittest.TestCase):
    def test_accepts_positive_integer(self):
        self.assertEqual(packet_analyzer.positive_integer("5"), 5)

    def test_rejects_non_positive_or_non_integer_values(self):
        for value in ("0", "-2", "abc"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    packet_analyzer.positive_integer(value)


class AnalyzePacketTests(unittest.TestCase):
    def test_identifies_supported_and_other_ip_protocols(self):
        packets = (
            (IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1234, dport=443), "TCP"),
            (IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=1234, dport=53), "UDP"),
            (IP(src="192.0.2.1", dst="198.51.100.1") / ICMP(), "ICMP"),
            (IP(src="192.0.2.1", dst="198.51.100.1", proto=47), "Other"),
        )

        for packet, expected_protocol in packets:
            with self.subTest(protocol=expected_protocol):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    protocol = packet_analyzer.analyze_packet(packet, 1)

                self.assertEqual(protocol, expected_protocol)
                self.assertIn(f"Protocol: {expected_protocol}", output.getvalue())

    def test_skips_non_ipv4_packets(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            protocol = packet_analyzer.analyze_packet(Ether() / ARP(), 1)

        self.assertIsNone(protocol)
        self.assertEqual(output.getvalue(), "")


class MainTests(unittest.TestCase):
    def test_reads_capture_and_obeys_packet_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            capture_path = Path(directory) / "sample.pcap"
            wrpcap(
                str(capture_path),
                [
                    Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(),
                    Ether() / IP(src="192.0.2.2", dst="198.51.100.2") / UDP(),
                ],
            )
            output = io.StringIO()
            with (
                patch.object(
                    sys,
                    "argv",
                    ["packet_analyzer.py", str(capture_path), "--limit", "1"],
                ),
                contextlib.redirect_stdout(output),
            ):
                result = packet_analyzer.main()

        self.assertEqual(result, 0)
        self.assertIn("Packets read: 1", output.getvalue())
        self.assertIn("TCP: 1", output.getvalue())
        self.assertNotIn("UDP: 1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
