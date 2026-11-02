
# Network Packet Analyzer

A command-line tool that reads an existing PCAP or PCAPNG capture and
summarizes IPv4 packet metadata. It does not capture live traffic or display
packet payloads. Analyze only capture files you are authorized to access.

## Features

- Displays source and destination IPv4 addresses
- Identifies TCP, UDP, ICMP, and other IPv4 protocols
- Displays packet timestamps, sizes, and TCP/UDP ports
- Prints totals for each protocol
- Optionally limits the number of packets analyzed
- Reads IPv4 packets only; non-IPv4 packets are skipped

## Requirements

- Python 3.10 or later
- Scapy

## Installation

From this directory, install the dependency:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Pass the path to an existing capture file:

```powershell
python packet_analyzer.py path\to\capture.pcap
```

To analyze only the first 100 packets:

```powershell
python packet_analyzer.py path\to\capture.pcapng --limit 100
```

Example output for a TCP packet:

```text
=======================================================
Packet Number: 1
Time: 1700000000.0
Source IP: 192.168.1.10
Destination IP: 192.168.1.20
Protocol: TCP
Packet Size: 60 bytes
Details: Source Port: 51514, Destination Port: 443
=======================================================
```

If PowerShell is open in the parent folder, include the project folder in the
script path:

```powershell
python .\Task1_Network_Packet_Analyzer\packet_analyzer.py path\to\capture.pcap
```

Run `python packet_analyzer.py --help` to see the available options.

## Tests

Run the test suite from this directory:

```powershell
python -m unittest discover -s tests -v
```

## Internship

CodSoft Cyber Security Internship — Task 1: Network Packet Analyzer
