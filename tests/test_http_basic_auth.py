
# Importing necessary libraries, including our own from relative path
from src.detections import Detect_HTTP_Basic_Auth
from scapy.layers.inet import IP, TCP
from scapy.all import Raw

# Generates scenario where detection should fire; triggers with pytest()
def test_HTTP_basic_auth_detected():
    
    # Creates raw byte string mimicking HTTP request w/ cleartext Authorization: Basic header
    Payload = (
        b"GET / HTTP/1.1\r\n"
        b"Authorization: Basic dXNlcjpwYXNz\r\n"
        b"\r\n"
    )

    # Creates a custom insecure HTTP packet with our custom payload
    Packet = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80) / Raw(load=Payload)

    # Mimicking policy condition
    Rule = {"enabled": True}

    # Runs detector against the custom packet
    Alert = Detect_HTTP_Basic_Auth(Packet, Rule)

    # Confirms a alert WAS raised
    assert Alert is not None

    # Confirms alert type is correct; didn't trigger a false alert
    assert Alert["type"] == "CLEARTEXT_HTTP_BASIC_AUTH"
