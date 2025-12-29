
# Importing necessary libraries, including our own from relative path
from src.detections import Detect_Disallowed_Ports
from scapy.layers.inet import IP, TCP

# Generates scenario where detection should fire; triggers with pytest()
def test_disallowed_port_triggers_alert():

    # Creates a custom insecure FTP packet
    Packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport = 12345, dport = 21)

    # Mimicking policy condition
    Rule = {
        "enabled": True,
        "ports": {"21": "FTP"},
        "severity": "medium"
    }

    # Runs detector against the custom packet
    Alert = Detect_Disallowed_Ports(Packet, Rule)

    # Confirms a alert WAS raised
    assert Alert is not None
    
    # Confirms alert type is correct; didn't trigger a false alert
    assert Alert["service"] == "FTP"
    assert Alert["dst_port"] == 21

# Alert should NOT trigger
def test_allowed_port_no_alert():

    # Creates a custom secure HTTPS packet
    Packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport = 12345, dport = 443)

    Rule = {
        "enabled": True,
        "ports": {"21": "FTP"}
    }

    Alert = Detect_Disallowed_Ports(Packet, Rule)

    # Confirms a alert was NOT raised
    assert Alert is None
