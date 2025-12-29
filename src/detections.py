from __future__ import annotations

import base64  # Used for decoding Basic authorization
from typing import Any, Dict, Optional, Tuple

# Allows for detailed analysis of packet data
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
from scapy.all import Raw

# Centralized IP logic for source and destination
def _Get_IP_Tuple(PacketData: Packet) -> Optional[Tuple[str, str]]:
    if IP not in PacketData:
        return None
    return PacketData[IP].src, PacketData[IP].dst

# Flags traffic on unauthorized ports
def Detect_Disallowed_Ports(PacketData: Packet, Rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not Rule.get("enabled", False):
        return None

    IP_Pair = _Get_IP_Tuple(PacketData)
    if not IP_Pair:
        return None

    Ports = Rule.get("ports", {})
    Severity = Rule.get("severity", "medium")

    # TCP
    if TCP in PacketData:
        SrcPort = int(PacketData[TCP].sport)
        DstPort = int(PacketData[TCP].dport)
        Service = Ports.get(str(DstPort)) or Ports.get(str(SrcPort))

        if Service:
            SrcIP, DstIP = IP_Pair
            return {
                "type": "DISALLOWED_PORT",
                "severity": Severity,
                "src_ip": SrcIP,
                "dst_ip": DstIP,
                "src_port": SrcPort,
                "dst_port": DstPort,
                "service": Service,
                "reason": f"Traffic observed on disallowed service port ({Service})."
            }

    # UDP
    if UDP in PacketData:
        SrcPort = int(PacketData[UDP].sport)
        DstPort = int(PacketData[UDP].dport)
        Service = Ports.get(str(DstPort)) or Ports.get(str(SrcPort))

        if Service:
            SrcIP, DstIP = IP_Pair
            return {
                "type": "DISALLOWED_PORT",
                "severity": Severity,
                "src_ip": SrcIP,
                "dst_ip": DstIP,
                "src_port": SrcPort,
                "dst_port": DstPort,
                "service": Service,
                "reason": f"Traffic observed on disallowed service port ({Service})."
            }

    return None

# Detects HTTP Basic Authentication sent in cleartext
def Detect_HTTP_Basic_Auth(PacketData: Packet, Rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Detects HTTP Basic Authentication sent in cleartext by inspecting payloads
    for Authorization: Basic <base64> headers.
    """
    if not Rule.get("enabled", False):
        return None

    if IP not in PacketData or TCP not in PacketData or Raw not in PacketData:
        return None

    Payload = bytes(PacketData[Raw].load)

    # Fast reject before decoding
    if b"Authorization: Basic " not in Payload:
        return None

    IP_Pair = _Get_IP_Tuple(PacketData)
    if not IP_Pair:
        return None

    SrcIP, DstIP = IP_Pair
    SrcPort = int(PacketData[TCP].sport)
    DstPort = int(PacketData[TCP].dport)

    Severity = Rule.get("severity", "high")

    Credentials = None
    try:
        Marker = b"Authorization: Basic "
        Start = Payload.index(Marker) + len(Marker)
        End = Payload.find(b"\r\n", Start)

        if End != -1:
            Encoded = Payload[Start:End].strip()
            Decoded = base64.b64decode(Encoded).decode("utf-8", errors="replace")
            Credentials = Decoded
    except Exception:
        pass

    Event = {
        "type": "CLEARTEXT_HTTP_BASIC_AUTH",
        "severity": Severity,
        "src_ip": SrcIP,
        "dst_ip": DstIP,
        "src_port": SrcPort,
        "dst_port": DstPort,
        "service": "HTTP",
        "reason": "HTTP Basic Authentication observed in cleartext."
    }

    if Credentials:
        Event["evidence"] = {"decoded_basic_auth": Credentials}

    return Event

# Detects cleartext FTP usernames and passwords
def Detect_FTP_Credentials(PacketData: Packet, Rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Detects FTP cleartext credentials by identifying USER and PASS commands.
    """
    if not Rule.get("enabled", False):
        return None

    if IP not in PacketData or TCP not in PacketData or Raw not in PacketData:
        return None

    Payload = bytes(PacketData[Raw].load)

    if b"USER " not in Payload and b"PASS " not in Payload:
        return None

    IP_Pair = _Get_IP_Tuple(PacketData)
    if not IP_Pair:
        return None

    SrcIP, DstIP = IP_Pair
    SrcPort = int(PacketData[TCP].sport)
    DstPort = int(PacketData[TCP].dport)
    Severity = Rule.get("severity", "high")

    User = None
    Password = None

    try:
        Text = Payload.decode("utf-8", errors="replace")
        for Line in Text.splitlines():
            LineUpper = Line.upper()
            if LineUpper.startswith("USER "):
                User = Line[5:].strip()
            if LineUpper.startswith("PASS "):
                Password = Line[5:].strip()
    except Exception:
        pass

    Event = {
        "type": "FTP_CLEARTEXT_CREDENTIALS",
        "severity": Severity,
        "src_ip": SrcIP,
        "dst_ip": DstIP,
        "src_port": SrcPort,
        "dst_port": DstPort,
        "service": "FTP",
        "reason": "FTP cleartext authentication command observed."
    }

    Evidence = {}
    if User:
        Evidence["user"] = User
    if Password:
        Evidence["password"] = Password
    if Evidence:
        Event["evidence"] = Evidence

    return Event

# Flags LLMNR / NBNS traffic based on UDP ports
def Detect_Legacy_Name_Resolution(PacketData: Packet, Rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not Rule.get("enabled", False):
        return None

    if IP not in PacketData or UDP not in PacketData:
        return None

    IP_Pair = _Get_IP_Tuple(PacketData)
    if not IP_Pair:
        return None

    UDP_Ports = Rule.get("udp_ports", {})
    Severity = Rule.get("severity", "low")

    SrcPort = int(PacketData[UDP].sport)
    DstPort = int(PacketData[UDP].dport)

    Protocol = UDP_Ports.get(str(DstPort)) or UDP_Ports.get(str(SrcPort))
    if not Protocol:
        return None

    SrcIP, DstIP = IP_Pair
    return {
        "type": "LEGACY_NAME_RESOLUTION",
        "severity": Severity,
        "src_ip": SrcIP,
        "dst_ip": DstIP,
        "src_port": SrcPort,
        "dst_port": DstPort,
        "service": Protocol,
        "reason": f"Legacy name resolution traffic observed ({Protocol})."
    }
