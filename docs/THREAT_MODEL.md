# Threat Model

This document outlines the high-level research threat model for the AERIS-PQ6G project. It defines the adversary capabilities and specific threat vectors that the future adaptive security framework is designed to detect, mitigate, or withstand.

## Research Threat Model (High-Level)

The framework is modeled against an active adversary capable of intercepting, modifying, and injecting traffic within the simulated 6G network. The ultimate adversary in this model is a **Quantum-Capable Adversary**, equipped with sufficiently mature quantum computing resources (e.g., Cryptographically Relevant Quantum Computers - CRQC) to break classical public-key cryptography in polynomial time. This adversary represents the future threat landscape that necessitates the transition to PQC.

## Potential Threats to be Studied (Future Phases)

The following specific threats will be modeled and evaluated in later stages of the project:

* **Unauthorized Device**: Attempts by non-provisioned or illegitimate devices to attach to the simulated 6G network.
* **Impersonation**: An adversary attempting to spoof the identity of a legitimate UE (User Equipment) or edge node.
* **Replay Behavior**: Capture and subsequent re-transmission of valid authentication or key establishment packets to gain unauthorized access or cause denial of service.
* **Suspicious Traffic**: Anomalous network flows indicative of reconnaissance, probing, or early-stage attack propagation.
* **Compromised Device**: A previously authenticated and legitimate device that has been overtaken by an adversary and is now exhibiting malicious behavior.
* **Man-in-the-Middle (MitM) Scenario**: An adversary positioned logically between a device and the edge/core, attempting to intercept or alter cryptographic handshakes.
* **Quantum-Capable Adversary**: The overarching future threat model where the adversary possesses capabilities to break ECC/RSA, requiring the system to fallback to or mandate PQC.

## Simulated vs. Real-World Attacks

**Important Distinction:** All threats modeled in this project are strictly *simulated threats*. They will be implemented programmatically as scripts or crafted network packets designed to trigger the risk assessment and adaptive security mechanisms within our controlled experimental testbed. They are not real-world exploits, and the evaluation does not constitute a certification of security against actual in-the-wild attacks. The purpose is strictly to evaluate the behavior and performance of the proposed adaptive algorithms.
