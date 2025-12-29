# Detection Modules

SentinelNet detection modules are independent functions that evaluate individual packets against policy-defined conditions. Each detector returns either a structured alert or no result.

---

## Disallowed Port Detection

**Purpose**  
Identifies traffic using ports explicitly marked as disallowed.

**Trigger Condition**
- TCP or UDP traffic observed on a configured port

**Typical Use Case**
- Identifying legacy services such as FTP, Telnet, or SMB
- Enforcing internal service policies

---

## HTTP Basic Authentication Detection

**Purpose**  
Detects HTTP Basic Authentication credentials transmitted in cleartext.

**Trigger Condition**
- TCP payload containing an `Authorization: Basic` header

**Notes**
- Best-effort decoding of credentials
- No TCP stream reconstruction

---

## FTP Cleartext Credential Detection

**Purpose**  
Detects cleartext FTP authentication commands.

**Trigger Condition**
- Presence of `USER` or `PASS` commands in FTP control traffic

**Notes**
- Credentials may be partial depending on packet boundaries
- Detection is protocol-aware but payload-based

---

## Legacy Name Resolution Detection

**Purpose**  
Identifies legacy name resolution protocols.

**Trigger Condition**
- UDP traffic on known LLMNR or NBNS ports

**Typical Use Case**
- Highlighting environments vulnerable to name resolution spoofing attacks
