# Alert Schema

SentinelNet generates structured alerts for each detected policy violation.  
Each alert represents a **single observation** of network activity that violates a defined rule.

Alerts are designed to be:
- Machine-readable for automation and SIEM ingestion
- Human-readable for manual analysis and validation
- Self-describing and explainable

---

## Core Alert Fields

All SentinelNet alerts include the following fields:

- **timestamp**  
  UTC timestamp indicating when the packet was observed and the alert was generated.

- **type**  
  Identifier describing the detection category (for example, `DISALLOWED_PORT` or `CLEARTEXT_HTTP_BASIC_AUTH`).

- **severity**  
  Severity level assigned by the active policy rule (for example, `low`, `medium`, `high`).

- **src_ip**  
  Source IP address observed in the packet.

- **dst_ip**  
  Destination IP address observed in the packet.

- **src_port**  
  Source transport-layer port.

- **dst_port**  
  Destination transport-layer port.

- **service**  
  Associated service or protocol name derived from the detection logic or policy configuration.

- **reason**  
  Human-readable explanation describing why the alert was generated.

---

## Optional Context Fields

Some alerts may include additional contextual fields when supporting data is available:

- **evidence**  
  Extracted data supporting the detection, such as decoded credentials or protocol-specific details.

- **detector**  
  Name of the detection module that generated the alert.

- **tool**  
  Identifier of the generating tool (for example, `SentinelNet`).

---

## Output Formats

Alerts are written to multiple formats to support different use cases:

- **JSONL (`alerts.jsonl`)**  
  Machine-readable format suitable for parsing, automation, or SIEM ingestion.  
  Each line represents a single alert event.

- **Plain Text Logs (`alerts.log`)**  
  Human-readable log entries intended for manual review and analysis.

Both formats represent the same alert data and are generated simultaneously unless otherwise configured in the policy file.
