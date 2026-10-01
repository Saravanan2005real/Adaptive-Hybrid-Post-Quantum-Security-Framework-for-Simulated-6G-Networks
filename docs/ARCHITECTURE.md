# AERIS-PQ6G Architecture

## Overview
AERIS-PQ6G is a simulated 6G network environment designed to test and validate adaptive post-quantum cryptographic security frameworks. 

## Layers

1. **Network Layer (Step 2)**
   - Simulates physical and logical topologies: Devices → Edge Nodes → Core Nodes.
   - Handles message delivery and basic routing logic.

2. **Security Primitives (Steps 3-6)**
   - **Classical**: Ed25519 (Auth), X25519 (KEM), AES-256-GCM.
   - **PQC**: ML-DSA-65 (Auth), ML-KEM-768 (KEM), AES-256-GCM.
   - **Hybrid**: Combined Ed25519 + ML-DSA-65 (Auth), X25519 + ML-KEM-768 (KEM).
   - Provides mutual authentication, challenge-response lifecycles, and session-scoped replay protection.

3. **Security Environment / Context Layer (Step 7)**
   - Acts as a metadata and context tracking layer that sits above the Network Simulator and Security Primitives.
   - Maintains a safe, strict registry of Devices, Edges, Cores, Communication Contexts, and Security Contexts.
   - Tracks authentication states, supported capabilities, active security modes (CLASSICAL, PQC, HYBRID), and telemetry over simulation time.
   - **Important Limitation:** It intentionally does *not* contain private keys, session keys, risk scoring logic, machine learning, or adaptive mode switching. Its sole responsibility is to provide a deterministic, safe, serializable snapshot of the 6G ecosystem's security posture at any point in simulation time.
   - **Step 7 observes and represents security context.**
   - **It does NOT:**
     - detect attacks
     - calculate risk
     - predict threats
     - make security decisions
     - adapt security modes

---

## Future Layers

4. **Risk Assessment (Step 8)**
   - Will consume the environment snapshots to calculate risk scores based on telemetry and state.

5. **Security Decision Engine (Step 9)**
   - Will use risk scores to trigger security mode changes.

6. **ML Risk Prediction (Step 10)**
   - Will introduce predictive threat modeling for adaptive decisions.

7. **Adaptive Security (Step 11)**
   - The fully integrated adaptive security framework dynamically responding to threats.
