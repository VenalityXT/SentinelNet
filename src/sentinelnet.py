from __future__ import annotations # Allows for cleaner type hints

import argparse                    # Allows script to be run with options (--policy, --iface, --count)
from typing import Any, Dict       # Helps describe data expectations

from scapy.all import sniff        # The engine of our packet capture

from policy import LoadPolicy   # type: ignore
from logger import AlertLogger  # type: ignore
from detections import (        # type: ignore
    Detect_Disallowed_Ports,
    Detect_HTTP_Basic_Auth,
    Detect_FTP_Credentials,
    Detect_Legacy_Name_Resolution,
)

# Establishing a list of "things to check" using the policy file
# Each tuple is (detector name, function to run, config for that function)
def Build_Detectors(rules: Dict[str, Any]):
    return [
        ("disallowed_ports", Detect_Disallowed_Ports, rules.get("disallowed_ports", {})),
        ("cleartext_http_basic_auth", Detect_HTTP_Basic_Auth, rules.get("cleartext_http_basic_auth", {})),
        ("ftp_cleartext_credentials", Detect_FTP_Credentials, rules.get("ftp_cleartext_credentials", {})),
        ("legacy_name_resolution", Detect_Legacy_Name_Resolution, rules.get("legacy_name_resolution", {})),
    ]


def main() -> None:
    # Establishing command line options
    parser = argparse.ArgumentParser(description = "SentinelNet - passive network detection tool")
    parser.add_argument("--policy", default = "policies/default.json", help = "Path to policy JSON file")
    parser.add_argument("--iface", default = None, help = "Network interface to sniff on (overrides policy)")
    parser.add_argument("--count", type = int, default=0, help = "Stop after N packets (0 = unlimited)")
    args = parser.parse_args()

    SentinelNetPolicy = LoadPolicy(args.policy)

    # Capture configuration 
    Capture_CFG = SentinelNetPolicy.capture

    IFace = args.iface or Capture_CFG.get("interface")
    BPF_Filtering = Capture_CFG.get("bpf_filter", "TCP or UDP")
    Store = bool(Capture_CFG.get("store_packets", False))

    # Set where alerts are written
    Output_CFG = SentinelNetPolicy.output
    Logger = AlertLogger(
        Alerts_Path = Output_CFG.get("alerts_path", "logs/alerts.jsonl"),
        Console = bool(Output_CFG.get("console", True))
    )

    Detectors = Build_Detectors(SentinelNetPolicy.rules)

    # Running check on every detector for each packet
    def On_Packet(Packet):
        for DetectorName, fn, RuleConfig in Detectors:

            # Each detector either returns None or an alert
            Alert = fn(Packet, RuleConfig)
            
            if Alert:
                Alert.setdefault("tool", "SentinelNet")
                Alert.setdefault("detector", DetectorName)
                Logger.Write(Alert)

    print(f"[SentinelNet] iface={IFace} filter='{BPF_Filtering}' count={args.count if args.count else 'unlimited'}")

    # Packet capture sniff()
    sniff(
        iface = IFace,
        filter = BPF_Filtering,
        prn = On_Packet,
        store = Store,
        count = args.count if args.count > 0 else 0,
    )


if __name__ == "__main__":
    main()
