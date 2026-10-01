import random
import yaml
from typing import Dict, Any, List
from src.events import EventLogger, EventType
from src.models import Device, DeviceType, EdgeNode, CoreNode
from src.network import Network

class Simulator:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.random_seed = self.config.get('simulation', {}).get('random_seed', 42)
        random.seed(self.random_seed)
        
        self.logger = EventLogger()
        self.network = Network(self.logger)
        
        self.duration = self.config.get('simulation', {}).get('duration', 100)
        self.message_rate = self.config.get('simulation', {}).get('message_generation_rate', 0.1)
        self.current_tick = 0
        self.total_messages_generated = 0

    def initialize_network(self):
        net_cfg = self.config.get('network', {})
        num_devices = net_cfg.get('num_devices', 10)
        num_edges = net_cfg.get('num_edge_nodes', 2)
        num_cores = net_cfg.get('num_core_nodes', 1)
        node_caps = net_cfg.get('node_capabilities', {})
        
        dev_cap = node_caps.get('device', {'compute': 10.0, 'memory': 16.0, 'battery': 100.0})
        edge_cap = node_caps.get('edge', {'capacity': 100.0})
        core_cap = node_caps.get('core', {'capacity': 1000.0})

        # Create Cores
        core_ids = []
        for i in range(num_cores):
            core_id = f"core-{i}"
            core = CoreNode(core_id, capacity=core_cap.get('capacity', 1000.0))
            self.network.add_core(core, timestamp=0)
            core_ids.append(core_id)
        
        # Create Edges
        edge_ids = []
        for i in range(num_edges):
            edge_id = f"edge-{i}"
            edge = EdgeNode(edge_id, capacity=edge_cap.get('capacity', 100.0))
            self.network.add_edge(edge, timestamp=0)
            # Connect to a random core
            target_core = random.choice(core_ids)
            self.network.connect_edge_to_core(edge_id, target_core, timestamp=0)
            edge_ids.append(edge_id)

        # Create Devices
        device_types = list(DeviceType)
        for i in range(num_devices):
            device_id = f"dev-{i}"
            dev_type = random.choice(device_types)
            device = Device(device_id, dev_type, compute=dev_cap.get('compute', 10.0), memory=dev_cap.get('memory', 16.0), battery=dev_cap.get('battery', 100.0))
            self.network.add_device(device, timestamp=0)
            # Connect to a random edge
            target_edge = random.choice(edge_ids)
            self.network.connect_device_to_edge(device_id, target_edge, timestamp=0)

    def run(self):
        self.initialize_network()
        
        for tick in range(1, self.duration + 1):
            self.current_tick = tick
            
            # Message generation phase
            core_ids = list(self.network.cores.keys())
            for device in self.network.devices.values():
                if random.random() < self.message_rate:
                    target_core = random.choice(core_ids)
                    msg = device.generate_message(
                        target_core_id=target_core,
                        payload={"data": "sensor_reading", "val": random.random()},
                        size=256,
                        timestamp=tick
                    )
                    self.logger.log(EventType.MESSAGE_CREATED, tick, message_id=msg.message_id, device_id=device.device_id, target_core_id=target_core)
                    self.total_messages_generated += 1
            
            # Network routing phase
            self.network.step(tick)

    def get_summary(self) -> Dict[str, Any]:
        stats = self.network.get_stats()
        stats["total_messages_generated"] = self.total_messages_generated
        stats["simulation_duration_ticks"] = self.duration
        stats["throughput_msgs_per_tick"] = stats["total_delivered_responses"] / self.duration if self.duration > 0 else 0
        return stats
