# Research Objectives

The AERIS-PQ6G project aims to achieve the following core research objectives incrementally:

1. **Build a 6G-style simulated network environment**: Create a testbed that structurally mimics the components of a 6G network (Devices, Edge, Core) to host the security framework.
2. **Establish a conventional cryptographic baseline**: Implement classical cryptographic protocols (e.g., standard ECC/RSA based authentication and key exchange) to serve as a benchmark for performance and security.
3. **Implement standardized post-quantum cryptographic mechanisms**: Integrate selected PQC algorithms to provide quantum-resistant authentication and confidentiality.
4. **Implement hybrid classical + post-quantum protection**: Develop mechanisms that combine classical and PQC algorithms to ensure security as long as at least one of the underlying schemes remains secure.
5. **Develop security-risk assessment**: Formulate logic to evaluate current network threats and vulnerabilities in real-time.
6. **Develop adaptive security selection**: Create a dynamic policy engine capable of switching between classical, purely PQC, and hybrid modes based on the current risk assessment and available resources.
7. **Investigate ML-based risk prediction**: Design and train machine learning models to predict incoming threats and proactively adapt the security posture.
8. **Simulate controlled attacks**: Develop scripts and tools to introduce specific, controlled threat scenarios into the simulated environment for testing.
9. **Evaluate security and performance**: Measure the effectiveness of the adaptive framework against threats and its impact on network resources.
10. **Compare Classical vs PQC vs Hybrid vs Adaptive Hybrid**: Conduct a comprehensive comparative analysis across these four paradigms to demonstrate the benefits and trade-offs of the proposed AERIS-PQ6G architecture.
