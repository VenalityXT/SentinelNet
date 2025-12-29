# Policy Configuration Reference

SentinelNet behavior is fully controlled through a JSON-based policy file. This file defines capture behavior, detection rules, and output settings.

---

## Capture Section

Controls how SentinelNet listens to network traffic.

**Common Fields**
- interface: Network interface to monitor
- bpf_filter: Berkeley Packet Filter expression
- store_packets: Whether packets are retained in memory

---

## Rules Section

Defines which detections are enabled and how they behave.

Each rule may include:
- enabled: Boolean toggle
- severity: Alert severity level
- rule-specific configuration fields

Rules are evaluated independently and may be enabled or disabled without affecting others.

---

## Output Section

Controls alert logging behavior.

**Common Fields**
- alerts_path: Path to JSONL alert file
- console: Enable or disable console output

Output paths are resolved relative to the project root.
