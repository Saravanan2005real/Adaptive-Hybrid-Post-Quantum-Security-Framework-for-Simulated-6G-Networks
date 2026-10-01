# Experiment Plan

This document outlines the preliminary evaluation plan for the AERIS-PQ6G framework. 

> **Note**: No experiments have been conducted yet. This document establishes the methodology for future evaluation. Do NOT fabricate any results.

## Comparative Baselines

The core objective of the experimental phase is to conduct a rigorous comparative analysis across four distinct security paradigms. The experiments will evaluate:

1. **Classical Security**: The system operating strictly using traditional algorithms (e.g., standard ECC/RSA).
2. **Post-Quantum Security**: The system operating strictly using selected PQC algorithms.
3. **Hybrid Security**: The system operating using a static combination of classical and PQC algorithms simultaneously.
4. **Adaptive Hybrid Security (AERIS-PQ6G)**: The proposed system dynamically transitioning between the above states based on real-time risk and ML predictions.

## Potential Metrics

The evaluation will quantitatively measure both the performance overhead and the security efficacy of each paradigm. The following metrics will be collected during the simulated experiments:

### Performance Metrics
* **Authentication Latency**: Time taken to complete the initial device authentication handshake.
* **Key Establishment Latency**: Time taken to negotiate and establish symmetric session keys.
* **CPU Usage**: Computational overhead on the simulated UEs, Edge nodes, and Core components.
* **Memory Usage**: RAM footprint required to maintain cryptographic states and execute algorithms.
* **Communication Overhead**: The additional bandwidth consumed by larger PQC keys, signatures, and hybrid combinations.
* **Throughput**: The effective data transfer rate achievable under different security profiles.
* **Scalability**: The system's ability to maintain acceptable performance as the number of simulated devices increases.

### Security Metrics
* **Attack Detection Performance**: The speed and accuracy with which the ML and risk assessment modules identify the simulated threats defined in the Threat Model.
* **False-Positive Rate**: Instances where legitimate behavior is incorrectly flagged as a threat, triggering unnecessary security posture escalation.
* **False-Negative Rate**: Instances where a simulated threat goes undetected, resulting in the failure to elevate the security posture.

## Evaluation Methodology

The specific methodologies and advanced security simulation parameters will be developed in subsequent phases. 

**Currently Implemented:** 
1. **Network Baseline (`network_baseline.py`)**: Measures the raw performance of the unencrypted simulated network. It captures the following baseline metrics:
* **Generated Messages**: Total requests created by devices.
* **Delivered Responses**: Total requests that successfully completed a round trip.
* **Failed Messages**: Total messages dropped due to routing/connection issues.
* **In-Flight Messages**: Messages still traversing the network when the simulation terminates.
* **Average Response Latency**: The average number of ticks for a message to complete a round trip.
* **Throughput**: Responses delivered per simulation tick.
* **Execution Time**: The wall-clock time required to execute the simulation run.

2. **Classical Security Baseline (`classical_security_baseline.py`)**: Measures the performance and behavior of the conventional, classical security layer. The classical security implementation is a baseline for future comparison with post-quantum and hybrid security. It adds the following metrics:
* **Authenticated Sessions**: Total number of successfully negotiated sessions.
* **Authentication/Encryption/Decryption Failures**: Counts of cryptographic failures.
* **Replays Detected**: Count of rejected replayed messages.
* **Auth Latency (ms)**: High-resolution real-time processing latency for Ed25519 signing/verification.
* **Key Exch Latency (ms)**: High-resolution latency for X25519 and HKDF.
* **Encrypt/Decrypt Latency (ms)**: High-resolution latency for AES-GCM operations.
