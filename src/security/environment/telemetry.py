import time
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class TelemetryRecord:
    tick: int
    timestamp: float
    event_type: str
    context_id: str
    entity_id: str
    metadata: Dict[str, Any]

class TelemetryStore:
    def __init__(self):
        self.records: List[TelemetryRecord] = []
        
    def record(self, tick: int, event_type: str, context_id: str, entity_id: str, metadata: Dict[str, Any]):
        r = TelemetryRecord(tick, time.time(), event_type, context_id, entity_id, metadata)
        self.records.append(r)
        
    def get_snapshot(self) -> List[Dict[str, Any]]:
        return [
            {
                "tick": r.tick,
                "timestamp": r.timestamp,
                "event_type": r.event_type,
                "context_id": r.context_id,
                "entity_id": r.entity_id,
                "metadata": r.metadata
            }
            for r in self.records
        ]
