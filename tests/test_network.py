import pytest
import os
import yaml
from src.models import Device, DeviceType, EdgeNode, CoreNode
from src.events import EventLogger, EventType
from src.network import Network
from src.simulator import Simulator

def test_node_creation():
    dev = Device("dev-1", DeviceType.IOT_SENSOR, 10, 10, 100)
    assert dev.device_id == "dev-1"
    assert dev.device_type == DeviceType.IOT_SENSOR

    edge = EdgeNode("edge-1", 100)
    assert edge.edge_id == "edge-1"

    core = CoreNode("core-1", 1000)
    assert core.core_id == "core-1"

def test_routing_end_to_end():
    logger = EventLogger()
    net = Network(logger)
    
    dev = Device("dev-1", DeviceType.IOT_SENSOR, 10, 10, 100)
    edge = EdgeNode("edge-1", 100)
    core = CoreNode("core-1", 1000)
    
    net.add_device(dev, 0)
    net.add_edge(edge, 0)
    net.add_core(core, 0)
    
    net.connect_device_to_edge("dev-1", "edge-1", 0)
    net.connect_edge_to_core("edge-1", "core-1", 0)
    
    assert dev.connected_edge_id == "edge-1"
    assert "dev-1" in edge.connected_devices
    assert edge.connected_core_id == "core-1"
    
    # Generate message
    msg = dev.generate_message("core-1", {"test": "data"}, 100, 1)
    
    net.step(1)
    # After tick 1: Message is moved from device to edge uplink queue
    assert len(edge.uplink_queue) == 1
    assert edge.stats["messages_received_from_devices"] == 1
    
    net.step(2)
    # After tick 2: Message moved from edge uplink to core inbox
    assert len(core.inbox) == 1
    
    net.step(3)
    # After tick 3: Core processes inbox, generates response, puts in edge downlink
    assert core.stats["messages_received"] == 1
    assert core.stats["responses_generated"] == 1
    assert len(edge.downlink_queue) == 1
    
    net.step(4)
    # After tick 4: Edge moved response to Device
    assert edge.stats["responses_forwarded_to_devices"] == 1
    assert dev.stats["responses_received"] == 1
    assert len(net.delivered_messages) == 1
    
    latency = net.delivered_messages[0].delivery_timestamp - msg.creation_timestamp
    assert latency == 3

def test_explicit_events():
    logger = EventLogger()
    net = Network(logger)
    
    dev = Device("dev-1", DeviceType.IOT_SENSOR, 10, 10, 100)
    edge = EdgeNode("edge-1", 100)
    core = CoreNode("core-1", 1000)
    
    net.add_device(dev, 1)
    net.add_edge(edge, 2)
    net.add_core(core, 3)
    
    net.connect_device_to_edge("dev-1", "edge-1", 4)
    net.connect_edge_to_core("edge-1", "core-1", 5)
    
    dev.generate_message("core-1", {}, 100, 6)
    logger.log(EventType.MESSAGE_CREATED, 6, message_id="mock", device_id="dev-1", target_core_id="core-1")
    
    net.step(7) # device to edge
    net.step(8) # edge to core
    net.step(9) # core processes, generates response
    net.step(10) # edge delivers to device
    
    events = [e["event_type"] for e in logger.get_events()]
    
    assert EventType.DEVICE_CREATED.value in events
    assert EventType.EDGE_CREATED.value in events
    assert EventType.CORE_CREATED.value in events
    assert EventType.DEVICE_CONNECTED.value in events
    assert EventType.EDGE_CONNECTED_TO_CORE.value in events
    assert EventType.MESSAGE_CREATED.value in events
    assert EventType.MESSAGE_SENT.value in events
    assert EventType.MESSAGE_FORWARDED.value in events
    assert EventType.MESSAGE_RECEIVED.value in events
    assert EventType.RESPONSE_GENERATED.value in events
    assert EventType.RESPONSE_SENT.value in events
    assert EventType.MESSAGE_DELIVERED.value in events

def test_explicit_statistics():
    logger = EventLogger()
    net = Network(logger)
    
    dev = Device("dev-1", DeviceType.IOT_SENSOR, 10, 10, 100)
    edge = EdgeNode("edge-1", 100)
    core = CoreNode("core-1", 1000)
    
    net.add_device(dev, 0)
    net.add_edge(edge, 0)
    net.add_core(core, 0)
    net.connect_device_to_edge("dev-1", "edge-1", 0)
    net.connect_edge_to_core("edge-1", "core-1", 0)
    
    # 3 messages generated, 2 fully delivered, 1 in flight
    dev.generate_message("core-1", {}, 100, 1)
    dev.generate_message("core-1", {}, 100, 2)
    
    net.step(1)
    net.step(2)
    net.step(3)
    net.step(4) # first message delivered
    net.step(5) # second message delivered
    
    dev.generate_message("core-1", {}, 100, 6) # 3rd msg generated
    net.step(6) # sent to edge (in flight)
    
    stats = net.get_stats()
    
    assert stats["total_devices"] == 1
    assert stats["total_edges"] == 1
    assert stats["total_cores"] == 1
    assert stats["total_delivered_responses"] == 2
    assert stats["total_failed_messages"] == 0
    assert stats["in_flight_messages"] == 1
    assert stats["average_response_latency_ticks"] == 1.0

def test_multiple_devices():
    logger = EventLogger()
    net = Network(logger)
    
    core = CoreNode("core-1", 1000)
    edge1 = EdgeNode("edge-1", 100)
    edge2 = EdgeNode("edge-2", 100)
    dev1 = Device("dev-1", DeviceType.IOT_SENSOR, 10, 10, 100)
    dev2 = Device("dev-2", DeviceType.MOBILE_DEVICE, 10, 10, 100)
    dev3 = Device("dev-3", DeviceType.VEHICLE, 10, 10, 100)
    
    net.add_core(core, 0)
    net.add_edge(edge1, 0)
    net.add_edge(edge2, 0)
    net.add_device(dev1, 0)
    net.add_device(dev2, 0)
    net.add_device(dev3, 0)
    
    net.connect_edge_to_core("edge-1", "core-1", 0)
    net.connect_edge_to_core("edge-2", "core-1", 0)
    net.connect_device_to_edge("dev-1", "edge-1", 0)
    net.connect_device_to_edge("dev-2", "edge-1", 0)
    net.connect_device_to_edge("dev-3", "edge-2", 0)
    
    dev1.generate_message("core-1", {}, 100, 1)
    dev2.generate_message("core-1", {}, 100, 1)
    dev3.generate_message("core-1", {}, 100, 1)
    
    for i in range(1, 5):
        net.step(i)
        
    stats = net.get_stats()
    assert stats["total_delivered_responses"] == 3
    assert stats["in_flight_messages"] == 0
    assert dev1.stats["responses_received"] == 1
    assert dev2.stats["responses_received"] == 1
    assert dev3.stats["responses_received"] == 1
    assert core.stats["messages_received"] == 3

def test_configuration_loading():
    config = {
        "network": {
            "num_devices": 15,
            "num_edge_nodes": 3,
            "num_core_nodes": 2,
            "node_capabilities": {
                "device": {"compute": 5.0, "memory": 8.0, "battery": 50.0},
                "edge": {"capacity": 50.0},
                "core": {"capacity": 500.0}
            }
        },
        "simulation": {
            "duration": 20,
            "random_seed": 42,
            "message_generation_rate": 0.1
        }
    }
    os.makedirs("configs", exist_ok=True)
    with open("configs/test_config.yaml", "w") as f:
        yaml.dump(config, f)
        
    sim = Simulator("configs/test_config.yaml")
    sim.initialize_network()
    
    assert sim.duration == 20
    assert sim.random_seed == 42
    assert sim.message_rate == 0.1
    
    stats = sim.network.get_stats()
    assert stats["total_devices"] == 15
    assert stats["total_edges"] == 3
    assert stats["total_cores"] == 2
    
    # Check capabilities
    dev = list(sim.network.devices.values())[0]
    assert dev.compute == 5.0
    assert dev.memory == 8.0
    assert dev.battery == 50.0
    
    edge = list(sim.network.edges.values())[0]
    assert edge.capacity == 50.0
    
    core = list(sim.network.cores.values())[0]
    assert core.capacity == 500.0

def test_reproducibility():
    config = {
        "network": {"num_devices": 10, "num_edge_nodes": 2, "num_core_nodes": 1},
        "simulation": {"duration": 10, "random_seed": 123, "message_generation_rate": 0.5}
    }
    os.makedirs("configs", exist_ok=True)
    with open("configs/test_config.yaml", "w") as f:
        yaml.dump(config, f)
        
    sim1 = Simulator("configs/test_config.yaml")
    sim1.run()
    stats1 = sim1.get_summary()
    
    sim2 = Simulator("configs/test_config.yaml")
    sim2.run()
    stats2 = sim2.get_summary()
    
    assert stats1["total_messages_generated"] == stats2["total_messages_generated"]
    assert stats1["total_delivered_responses"] == stats2["total_delivered_responses"]
    assert stats1["average_response_latency_ticks"] == stats2["average_response_latency_ticks"]
    assert stats1["total_failed_messages"] == stats2["total_failed_messages"]
    assert stats1["in_flight_messages"] == stats2["in_flight_messages"]
