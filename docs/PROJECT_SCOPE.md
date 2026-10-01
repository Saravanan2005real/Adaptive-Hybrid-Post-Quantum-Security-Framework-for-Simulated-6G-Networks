# Project Scope

## What the Project Will Build
* A software-based simulation of a 6G-style network architecture (Devices, Edge, Core).
* A modular security framework integrating classical and post-quantum cryptographic primitives.
* An adaptive decision engine that selects the optimal cryptographic suite (classical, post-quantum, or hybrid) based on contextual data and risk levels.
* An ML-based risk prediction module that analyzes simulated network traffic and context to assess threats.
* An evaluation and metrics collection pipeline to measure latencies, overhead, and accuracy across different security profiles.

## What the Project Will Not Build
* A production-ready 6G core or radio access network (RAN).
* New post-quantum cryptographic algorithms (we will utilize existing standardized or candidate algorithms).
* Production-grade deployment tooling (e.g., Kubernetes manifests for scalable deployment in real telecom environments).
* A complete, enterprise-grade Intrusion Detection System (IDS).

## Assumptions
* Standardized PQC algorithms (e.g., NIST finalists) are available and can be integrated via external libraries when the implementation phase begins.
* The simulated network environment provides sufficient fidelity to represent the latency, bandwidth, and resource constraints of 6G networks for the purpose of relative performance comparison.
* The threat scenarios can be accurately modeled through simulated attack patterns.

## Scope Boundaries
The focus is strictly on the *adaptive selection* and *hybrid integration* of post-quantum security in a 6G context, along with evaluating the performance tradeoffs. The project bounds itself to the software prototype required to produce verifiable experimental results for a research paper.

## Expected Final Prototype
The final outcome will be an experimental testbed capable of running automated scenarios where simulated 6G devices authenticate and communicate. The testbed will record system performance and security resilience under varying simulated threat conditions and network states, generating output data for comparative analysis.
