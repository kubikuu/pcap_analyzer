from scapy.all import PcapReader, ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoReply,
    ICMPv6DestUnreach,
    ICMPv6EchoRequest,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6ND_RS,
    ICMPv6ND_RA,
)


class Parser:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path

    def get_packets(self):
        with PcapReader(self.file_path) as pcap_reader:
            for packet in pcap_reader:
                yield self.decode_packet(packet)

    def decode_packet(self, packet):
        timestamp = packet.time
        version = None
        length = len(packet)
        src = None
        dst = None
        sport = None
        dport = None
        protocol = None

        if packet.haslayer(IP):
            version = "IPv4"
            src = packet[IP].src
            dst = packet[IP].dst

        elif packet.haslayer(IPv6):
            version = "IPv6"
            src = packet[IPv6].src
            dst = packet[IPv6].dst

        elif packet.haslayer(ARP):
            version = "IPv4"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            protocol = "ARP"

        elif packet.haslayer(Ether):
            src = packet[Ether].src
            dst = packet[Ether].dst

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            protocol = "TCP"

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            protocol = "UDP"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        elif (
            packet.haslayer(ICMPv6EchoReply)
            or packet.haslayer(ICMPv6DestUnreach)
            or packet.haslayer(ICMPv6EchoRequest)
            or packet.haslayer(ICMPv6ND_NS)
            or packet.haslayer(ICMPv6ND_NA)
            or packet.haslayer(ICMPv6ND_RS)
            or packet.haslayer(ICMPv6ND_RA)
        ):
            protocol = "ICMPv6"

        if packet.haslayer(DNS) or packet.haslayer(DNSRR) or packet.haslayer(DNSQR):
            protocol = "DNS"

        if dport in (80, 8080) or sport in (80, 8080):
            protocol = "HTTP"

        elif dport == 443 or sport == 443:
            protocol = "HTTPS"

        return {
            "timestamp": timestamp,
            "version": version,
            "length": length,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "protocol": protocol,
        }
