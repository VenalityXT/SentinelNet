from __future__ import annotations      # Allows for cleaner type hints

import json                             # Parses JSON text into a dictionary
from dataclasses import dataclass       # Creates classes without boilerplate
from pathlib import Path                # More efficient file handling
from typing import Any, Dict            # Helps describe data expectations

# Read only container for policy data, preventing accidental changes
@dataclass(frozen=True)
class Policy:
    # Storing default.json as dictionary
    raw: Dict[str, Any]

    @property
    def capture(self) -> Dict[str, Any]:
        return self.raw.get("capture", {})
    
    @property
    def rules(self) -> Dict[str, Any]:
        return self.raw.get("rules", {})
    
    @property
    def output(self) -> Dict[str, Any]:
        return self.raw.get("output", {})
    
def LoadPolicy(PolicyPath: str) -> Policy:
    BaseDir = Path(__file__).resolve().parent.parent
    SentinelNetPolicyPath = (BaseDir / PolicyPath).resolve()

    # Prevents silent failures
    if not SentinelNetPolicyPath.exists():
        raise FileNotFoundError(f"Policy file not found: {PolicyPath}")
    
    Data = json.loads(SentinelNetPolicyPath.read_text(encoding="utf-8"))

    # Required key check
    if "rules" not in Data:
        raise ValueError("Policy file missing required key: 'rules'")
    
    return Policy(raw=Data)