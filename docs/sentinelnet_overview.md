# SentinelNet Overview

SentinelNet is a passive, policy-driven network detection tool designed to identify insecure or legacy network behavior through packet-level inspection. It operates as a lightweight visibility layer, producing structured alerts suitable for SOC workflows and human review.

---

## Purpose

SentinelNet is built to:
- Detect insecure protocols and authentication mechanisms
- Highlight policy violations in internal or edge networks
- Provide explainable, event-based alerts without active interference

SentinelNet intentionally avoids intrusion prevention, packet manipulation, or traffic blocking.

---

## High-Level Architecture

SentinelNet follows a simple, stream-based processing model:

Packet Capture  
→ Detector Engine  
→ Alert Generation  
→ Log Output

```mermaid
---
config:
  layout: dagre
---
flowchart TB
    A["Network Interface"] --> B["Scapy Packet Capture"]
    B --> C["BPF Filter"]
    C --> D["Packet Dispatcher"]
    D --> E1["Disallowed Port Detector"] & E2["HTTP Basic Auth Detector"] & E3["FTP Credential Detector"] & E4["Legacy Name Resolution Detector"]
    E1 --> F["Alert Generator"]
    E2 --> F
    E3 --> F
    E4 --> F
    F --> G1["alerts.jsonl<br>Machine Readable"] & G2["Console Output"] & G3["alerts.log<br>Human Readable"]

    G3@{ shape: rect}
```

Each packet is processed independently. When a policy condition is met, an alert is generated and logged immediately.

---

## Detection Model

- Stateless packet inspection
- One packet evaluated at a time
- No packet buffering or stream reconstruction
- All detection behavior controlled via policy configuration

This design favors stability, low resource usage, and predictable behavior.

---

## Output Model

SentinelNet produces two forms of output:
- JSONL alerts for machine ingestion and automation
- Human-readable log entries for manual review

Both outputs are generated from the same alert event.

---

## Intended Use

SentinelNet is intended for:
- Learning and experimentation
- Home lab and internal network visibility
- Demonstrating detection engineering concepts

It is not intended to replace full IDS or NDR platforms.
