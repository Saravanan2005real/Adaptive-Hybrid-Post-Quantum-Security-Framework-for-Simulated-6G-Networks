from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import uuid

class DeviceType(Enum):
    IOT_SENSOR = "IoT Sensor"
    MOBILE_DEVICE = "Mobile Device"
    VEHICLE = "Vehicle"
    INDUSTRIAL = "Industrial Device"

class MessageStatus(Enum):
    CREATED = "CREATED"
    SENT_TO_EDGE = "SENT_TO_EDGE"
    FORWARDED_TO_CORE = "FORWARDED_TO_CORE"
    PROCESSED_BY_CORE = "PROCESSED_BY_CORE"
    RESPONSE_SENT = "RESPONSE_SENT"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"

@dataclass
class Message:
    message_id: str
    source_id: str
    destination_id: str
    payload: Dict[str, Any]
    size: int
    status: MessageStatus = MessageStatus.CREATED
    creation_timestamp: int = -1
    delivery_timestamp: int = -1
    is_response: bool = False
    original_message_id: Optional[str] = None

class Device:
    def __init__(self, device_id: str, device_type: DeviceType, compute: float, memory: float, battery: float):
        self.device_id = device_id
        self.device_type = device_type
        self.compute = compute
        self.memory = memory
        self.battery = battery
        self.connected_edge_id: Optional[str] = None
        self.stats = {
            "messages_generated": 0,
            "messages_sent": 0,
            "responses_received": 0,
            "failed_messages": 0
        }
        self.pending_messages: List[Message] = []

    def generate_message(self, target_core_id: str, payload: Dict[str, Any], size: int, timestamp: int) -> Message:
        msg = Message(
            message_id=str(uuid.uuid4()),
            source_id=self.device_id,
            destination_id=target_core_id,
            payload=payload,
            size=size,
            creation_timestamp=timestamp
        )
        self.pending_messages.append(msg)
        self.stats["messages_generated"] += 1
        return msg

    def receive_response(self, msg: Message, timestamp: int):
        msg.status = MessageStatus.DELIVERED
        msg.delivery_timestamp = timestamp
        self.stats["responses_received"] += 1

class EdgeNode:
    def __init__(self, edge_id: str, capacity: float):
        self.edge_id = edge_id
        self.capacity = capacity
        self.connected_devices: List[str] = []
        self.connected_core_id: Optional[str] = None
        self.stats = {
            "messages_received_from_devices": 0,
            "messages_forwarded_to_core": 0,
            "responses_received_from_core": 0,
            "responses_forwarded_to_devices": 0
        }
        # queues for routing
        self.uplink_queue: List[Message] = [] # device -> core
        self.downlink_queue: List[Message] = [] # core -> device

    def receive_from_device(self, msg: Message):
        self.stats["messages_received_from_devices"] += 1
        msg.status = MessageStatus.SENT_TO_EDGE
        self.uplink_queue.append(msg)

    def receive_from_core(self, msg: Message):
        self.stats["responses_received_from_core"] += 1
        self.downlink_queue.append(msg)

class CoreNode:
    def __init__(self, core_id: str, capacity: float):
        self.core_id = core_id
        self.capacity = capacity
        self.connected_edges: List[str] = []
        self.stats = {
            "messages_received": 0,
            "responses_generated": 0
        }
        self.inbox: List[Message] = []
        self.outbox: List[Message] = []

    def receive_from_edge(self, msg: Message):
        self.stats["messages_received"] += 1
        msg.status = MessageStatus.FORWARDED_TO_CORE
        self.inbox.append(msg)

    def generate_response(self, original_msg: Message, timestamp: int) -> Message:
        self.stats["responses_generated"] += 1
        original_msg.status = MessageStatus.PROCESSED_BY_CORE
        
        response_msg = Message(
            message_id=str(uuid.uuid4()),
            source_id=self.core_id,
            destination_id=original_msg.source_id,
            payload={"ack": True, "status": "ok"},
            size=128,
            status=MessageStatus.RESPONSE_SENT,
            creation_timestamp=timestamp,
            is_response=True,
            original_message_id=original_msg.message_id
        )
        self.outbox.append(response_msg)
        return response_msg
