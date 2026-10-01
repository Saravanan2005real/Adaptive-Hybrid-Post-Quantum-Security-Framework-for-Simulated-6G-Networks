# AERIS-PQ6G Final Prototype Freeze

## Project Name
Adaptive Hybrid Post-Quantum Security Framework for Simulated 6G Networks (AERIS-PQ6G)

## Frozen Architecture
The AERIS-PQ6G software simulation prototype represents a structurally complete simulated 6G environment designed for experimental evaluation of adaptive hybrid post-quantum cryptography. It integrates Devices, Edge Nodes, and Core Nodes into a purely architectural/protocol simulation.

## Frozen Steps 1–17
- Step 1 Project Foundation
- Step 2 Network Simulation
- Step 3 Classical Security
- Step 4 PQC
- Step 5 Hybrid Security
- Step 6 Hybrid Authentication Protocol
- Step 7 6G Security Environment
- Step 8 Security Risk System
- Step 9 Security Decision Engine
- Step 10 ML Risk Prediction
- Step 11 Adaptive Security Orchestration
- Step 12 Attacker Simulation
- Step 13 Attack–Defense Experiments
- Step 14 Automated Experiments
- Step 15 Comprehensive Benchmarking
- Step 16 Scalability Testing
- Step 17 Stress Testing & Validation

## Cryptographic Primitives
- **Classical**: ED25519 (Signatures), X25519 (Key Exchange), ChaCha20-Poly1305 (AEAD)
- **Post-Quantum**: ML-DSA-65 (Signatures), ML-KEM-768 (Key Encapsulation)

## Security Modes
- `CLASSICAL`
- `PQC`
- `HYBRID`
- `ADAPTIVE_HYBRID`

## Adaptive Orchestration
The decision engine uses a fused risk score (combining rule-based heuristics and a deterministic ML model) combined with a stateful hysteresis cooldown to determine the optimal security mode transition. 

## Attacker Simulation Scope
Synthetic attack injection supporting:
- AUTHENTICATION_ATTACK
- REPLAY_ATTACK
- MESSAGE_TAMPERING_ATTACK
- SESSION_ABUSE_ATTACK
- RESOURCE_PRESSURE_ATTACK

## Experiment/Benchmark Scope
All automated experiments and benchmarks (Steps 15, 16, 17) evaluate throughput, latency (in discrete simulation ticks), overhead, and transition stability.

## Validation Status
The system has passed 100% of all unit, functional, integration, scalability, and stress tests.

## Known Limitations
- This is a software simulation prototype. Simulated timing metrics (ticks) do NOT correspond to physical network latency in real-world 6G hardware.
- The ML risk prediction uses a purely synthetic, deterministic model built for the simulation. It is not validated real-world attack prediction.
- This framework does NOT claim production 6G deployment or readiness.

## Reproducibility Information
All results are 100% reproducible via frozen random seed logic and deterministic matrix execution paths. Benchmark artifacts are statically generated and preserved.

## Step 18 Dashboard Constraints
The Step 18 web dashboard is explicitly designed as a PRESENTATION/INTEGRATION ONLY layer. The dashboard code must not and does not alter the validated research results, cryptographic implementations, risk logic, or benchmark datasets in any capacity.
