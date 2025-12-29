# Detection Modules

SentinelNet detection modules are independent, stateless functions that evaluate individual packets against policy-defined conditions.  
Each detector inspects packet metadata and, when applicable, payload content to determine whether a policy violation has occurred.

Detectors operate independently and return either:
- A structured alert describing the violation, or
- No result if no violation is detected

This modular design allows detection logic to be enabled, disabled, or extended without affecting other components.

---

## Disallowed Port Detection

**Purpose**  
Identifies network traffic using ports explicitly marked as disallowed by policy.

**Trigger Conditions**
- TCP or UDP traffic observed on a configured source or destination port
- Port mappings defined in the active policy file

**Detection Method**
- Transport-layer inspection of TCP and UDP headers
- Policy-based port matching

**Typical Use Cases**
- Identifying legacy or insecure services such as FTP or Telnet
- Enforcing internal service exposure policies
- Highlighting unauthorized service usage

---

## HTTP Basic Authentication Detection

**Purpose**  
Detects HTTP Basic Authentication credentials transmitted in cleartext.

**Trigger Conditions**
- TCP traffic containing an HTTP payload
- Presence of an `Authorization: Basic` header in the packet payload

**Detection Method**
- Payload inspection of individual packets
- Best-effort Base64 decoding of credentials when possible

**Notes**
- No TCP stream reassembly is performed
- Credentials may appear incomplete depending on packet boundaries
- Detection is intended for visibility, not credential harvesting

---

## FTP Cleartext Credential Detection

**Purpose**  
Identifies FTP authentication commands transmitted without encryption.

**Trigger Conditions**
- TCP payload containing `USER` or `PASS` commands

**Detection Method**
- Payload inspection of FTP control traffic
- Pattern matching for authentication commands

**Notes**
- Credentials may be partial depending on packet segmentation
- Detection does not require strict port enforcement, allowing visibility into non-standard configurations

---

## Legacy Name Resolution Detection

**Purpose**  
Identifies legacy name resolution protocols commonly disabled in hardened environments.

**Trigger Conditions**
- UDP traffic observed on known legacy ports, such as:
  - LLMNR (UDP 5355)
  - NBNS (UDP 137)

**Detection Method**
- Transport-layer inspection of UDP packets
- Policy-driven port and protocol identification

**Typical Use Cases**
- Highlighting unnecessary attack surface
- Identifying environments susceptible to name resolution poisoning or relay attacks

---

## Detector Output

Each detection module generates a structured alert that includes:
- Source and destination context
- Protocol and service identification
- Policy rule violated
- Severity level and explanatory reasoning

All detectors share a common alert schema to ensure consistent logging and downstream analysis.
