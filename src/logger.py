from __future__ import annotations      # Allows for cleaner type hints

import json                             # Converts dictionaries into JSON strings
from datetime import datetime, timezone # Generates universal timestamps
from pathlib import Path                # More efficient file handling
from typing import Any, Dict            # Helps describe data expectations


def Get_Timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec = "seconds")

class AlertLogger:
    def __init__(
        self,
        Alerts_Path: str,
        Console: bool = True,
        Text_Log_Path: str = "logs/alerts.log"
    ) -> None:
        BaseDir = Path(__file__).resolve().parent.parent

        self.Alerts_Path = (BaseDir / Alerts_Path).resolve()
        self.Text_Log_Path = (BaseDir / Text_Log_Path).resolve()
        self.Console = Console

        # Ensure directories exist
        self.Alerts_Path.parent.mkdir(parents=True, exist_ok=True)
        self.Text_Log_Path.parent.mkdir(parents=True, exist_ok=True)

    def _Format_Text_Log(self, Event: Dict[str, Any]) -> str:
        Timestamp = Event.get("timestamp", "UNKNOWN_TIME")
        Severity = Event.get("severity", "unknown").upper()
        EventType = Event.get("type", "UNKNOWN_EVENT")

        SrcIP = Event.get("src_ip", "?")
        DstIP = Event.get("dst_ip", "?")
        SrcPort = Event.get("src_port", "?")
        DstPort = Event.get("dst_port", "?")
        Service = Event.get("service", "?")

        return (
            f"[{Timestamp}] {Severity} {EventType} "
            f"src={SrcIP}:{SrcPort} dst={DstIP}:{DstPort} "
            f"service={Service}"
        )

    # Writes new alerts to log file and console
    def Write(self, Event: Dict[str, Any]) -> None:
        Event = dict(Event)
        Event.setdefault("timestamp", Get_Timestamp())

        # JSONL output
        JsonLine = json.dumps(Event, ensure_ascii=False)
        with self.Alerts_Path.open("a", encoding="utf-8") as JsonFile:
            JsonFile.write(JsonLine + "\n")

        # Human readable log output
        TextLine = self._Format_Text_Log(Event)
        with self.Text_Log_Path.open("a", encoding="utf-8") as TextFile:
            TextFile.write(TextLine + "\n")

        # Optional console output (human-readable)
        if self.Console:
            print(TextLine)