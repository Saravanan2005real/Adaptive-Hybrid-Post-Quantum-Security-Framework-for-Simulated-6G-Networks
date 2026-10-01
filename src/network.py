from typing import Dict, Any, List, Optional
from src.models import Device, EdgeNode, CoreNode, Message
from src.events import EventLogger, EventType

class Network:
    def __init__(self, logger: EventLogger):
        self.devices: Dict[str, Device] = {}
        self.edges: Dict[str, EdgeNode] = {}
        self.cores: Dict[str, CoreNode] = {}
        self.logger = logger
        self.delivered_messages: List[Message] = []
        self.failed_messages: List[Message] = []

    def add_device(self, device: Device, timestamp: int):
        self.devices[device.device_id] = device
        self.logger.log(EventType.DEVICE_CREATED, timestamp, device_id=device.device_id, type=device.device_type.value)

    def add_edge(self, edge: EdgeNode, timestamp: int):
        self.edges[edge.edge_id] = edge
        self.logger.log(EventType.EDGE_CREATED, timestamp, edge_id=edge.edge_id)

    def add_core(self, core: CoreNode, timestamp: int):
        self.cores[core.core_id] = core
        self.logger.log(EventType.CORE_CREATED, timestamp, core_id=core.core_id)

    def connect_device_to_edge(self, device_id: str, edge_id: str, timestamp: int):
        device = self.devices.get(device_id)
        edge = self.edges.get(edge_id)
        if device and edge:
            device.connected_edge_id = edge_id
            edge.connected_devices.append(device_id)
            self.logger.log(EventType.DEVICE_CONNECTED, timestamp, device_id=device_id, edge_id=edge_id)
    
    def connect_edge_to_core(self, edge_id: str, core_id: str, timestamp: int = 0):
        edge = self.edges.get(edge_id)
        core = self.cores.get(core_id)
        if edge and core:
            edge.connected_core_id = core_id
            core.connected_edges.append(edge_id)
            self.logger.log(EventType.EDGE_CONNECTED_TO_CORE, timestamp, edge_id=edge_id, core_id=core_id)

    def step(self, timestamp: int):
        # 1. Edges process downlink (Core -> Device)
        for edge in self.edges.values():
            downlink_processing = []
            while edge.downlink_queue:
                downlink_processing.append(edge.downlink_queue.pop(0))
            
            for msg in downlink_processing:
                device = self.devices.get(msg.destination_id)
                if device and device.connected_edge_id == edge.edge_id:
                    device.receive_response(msg, timestamp)
                    edge.stats["responses_forwarded_to_devices"] += 1
                    self.delivered_messages.append(msg)
                    self.logger.log(EventType.MESSAGE_DELIVERED, timestamp, message_id=msg.message_id, device_id=device.device_id, latency=msg.delivery_timestamp - msg.creation_timestamp)
                else:
                    self.failed_messages.append(msg)
                    self.logger.log(EventType.MESSAGE_FAILED, timestamp, message_id=msg.message_id, reason="Device not found or not connected to edge")

        # 2. Cores process inbox (Edge -> Core) and send to outbox
        for core in self.cores.values():
            inbox_processing = []
            while core.inbox:
                inbox_processing.append(core.inbox.pop(0))
                
            for msg in inbox_processing:
                self.logger.log(EventType.MESSAGE_RECEIVED, timestamp, message_id=msg.message_id, core_id=core.core_id)
                response = core.generate_response(msg, timestamp)
                self.logger.log(EventType.RESPONSE_GENERATED, timestamp, message_id=response.message_id, core_id=core.core_id, original_message_id=msg.message_id)
            
            # Cores push outbox to Edges
            outbox_processing = []
            while core.outbox:
                outbox_processing.append(core.outbox.pop(0))
                
            for msg in outbox_processing:
                # Find the edge the original device is connected to
                target_device = self.devices.get(msg.destination_id)
                if target_device and target_device.connected_edge_id:
                    edge = self.edges.get(target_device.connected_edge_id)
                    if edge and edge.connected_core_id == core.core_id:
                        edge.receive_from_core(msg)
                        self.logger.log(EventType.RESPONSE_SENT, timestamp, message_id=msg.message_id, core_id=core.core_id, edge_id=edge.edge_id)
                        continue
                self.failed_messages.append(msg)
                self.logger.log(EventType.MESSAGE_FAILED, timestamp, message_id=msg.message_id, reason="Could not route response to edge")

        # 3. Edges process uplink (Device -> Edge) and send to Core
        for edge in self.edges.values():
            uplink_processing = []
            while edge.uplink_queue:
                uplink_processing.append(edge.uplink_queue.pop(0))
            
            for msg in uplink_processing:
                core_id = edge.connected_core_id
                core = self.cores.get(core_id) if core_id else None
                if core:
                    core.receive_from_edge(msg)
                    edge.stats["messages_forwarded_to_core"] += 1
                    self.logger.log(EventType.MESSAGE_FORWARDED, timestamp, message_id=msg.message_id, edge_id=edge.edge_id, core_id=core.core_id)
                else:
                    self.failed_messages.append(msg)
                    self.logger.log(EventType.MESSAGE_FAILED, timestamp, message_id=msg.message_id, reason="Edge not connected to core")

        # 4. Devices send pending messages to Edge
        for device in self.devices.values():
            pending = []
            while device.pending_messages:
                pending.append(device.pending_messages.pop(0))
            
            for msg in pending:
                edge = self.edges.get(device.connected_edge_id) if device.connected_edge_id else None
                if edge:
                    edge.receive_from_device(msg)
                    device.stats["messages_sent"] += 1
                    self.logger.log(EventType.MESSAGE_SENT, timestamp, message_id=msg.message_id, device_id=device.device_id, edge_id=edge.edge_id)
                else:
                    self.failed_messages.append(msg)
                    self.logger.log(EventType.MESSAGE_FAILED, timestamp, message_id=msg.message_id, reason="Device not connected to edge")

    def get_stats(self) -> Dict[str, Any]:
        total_delivered = len(self.delivered_messages)
        total_failed = len(self.failed_messages)
        latencies = [m.delivery_timestamp - m.creation_timestamp for m in self.delivered_messages]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        
        total_generated = sum(d.stats["messages_generated"] for d in self.devices.values())
        in_flight = total_generated - total_delivered - total_failed

        return {
            "total_devices": len(self.devices),
            "total_edges": len(self.edges),
            "total_cores": len(self.cores),
            "total_delivered_responses": total_delivered,
            "total_failed_messages": total_failed,
            "in_flight_messages": in_flight,
            "average_response_latency_ticks": avg_latency
        }
