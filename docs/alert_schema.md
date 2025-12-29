# Alert Schema

SentinelNet alerts are structured as JSON objects. Each alert represents a single detected policy violation.

---

## Core Fields

All alerts include the following fields:

- timestamp: UTC timestamp of the event
- type: Detection type identifier
- severity: Severity level
- src_ip: Source IP address
- dst_ip: Destination IP address
- src_port: Source port
- dst_port: Destination port
- service: Associated service or protocol
- reason: Human-readable explanation

---

## Optional Fields

Some alerts may include additional context:

- evidence: Extracted data supporting the detection
- detector: Name of the detection module
- tool: Tool identifier

---

## Output Formats

Alerts are written to:
- JSONL for structured ingestion
- Plain text `.log` files for human readability

Each line represents a single alert event.
