# SDN-based-DDoS-Detection-and-Mitigation-using-Ryu-sFlow-and-Mininet

This project implements and validates an automated system for detecting and mitigating DDoS flooding attacks in an SDN environment.

The architecture uses Mininet to create a realistic network topology, sFlow-RT for real-time traffic analysis, and the Ryu SDN controller to dynamically install mitigation rules. The system is designed as a closed control loop: traffic is sampled via sFlow, an analysis script (ddos.js) detects anomalies by exceeding a predefined threshold, and a REST API call to Ryu triggers a DROP rule on the virtual switch, effectively blocking the attack at the data plane level.

The repository includes the configuration, the ddos.js detection script, and test results that demonstrate the system's effectiveness, robustness, and low impact on CPU resources, even under intense stress tests. The analysis also validates how the system preserves network quality by minimizing latency for legitimate traffic during an attack
