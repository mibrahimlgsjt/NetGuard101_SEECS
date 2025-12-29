# NetGuard: AI-Powered IDPS Technical Summary

**Project Name:** NetGuard
**Function:** Intrusion Detection and Prevention System (IDPS)
**Target Platform:** Android / Mobile IoT
**Date:** Dec 24, 2025

## 1. Abstract
NetGuard represents a next-generation approach to mobile security. As mobile devices increasingly become the primary target for cyberattacks, traditional rule-based firewalls fall short against zero-day exploits and polymorphic malware. NetGuard addresses this gap by implementing a **hybrid IDPS** that leverages local edge-AI (TensorFlow Lite) alongside established rule-based filtering to provide robust, real-time protection without compromising device performance or user privacy.

## 2. Problem Statement
Mobile devices are often connected to insecure public networks, exposing them to:
*   **Port Scanning:** Attackers probing for open vulnerabilities.
*   **DOS Attacks:** Attempts to overwhelm device network stacks.
*   **Data Exfiltration:** Unauthorized outgoing traffic.

Commercial solutions are often expensive, battery-draining, or rely entirely on cloud analysis (privacy risk).

## 3. Proposed Solution
NetGuard runs a lightweight security kernel (`AcademicSecurityManager`) directly on the device.
*   **Local Processing:** NO data leaves the device for analysis. Privacy is preserved.
*   **Hybrid Engine:**
    *   *Rules:* Blocks known malicious IPs instantaneously.
    *   *AI:* Detects deviations in traffic patterns that indicate novel attacks.
*   **Visualization:** A user-friendly Material Design (KivyMD) dashboard simplifies security for non-technical users.

## 4. Key Features & Implementation
*   **Traffic Sniffer:** Captures UDP/TCP packets in real-time. implementation uses raw sockets or simulation data for safe testing.
*   **Classification:** Uses a converted `.tflite` model for logical inference. Features include: `[packet_size, src_port, dst_port, protocol_type]`.
*   **Remote Auditing:** Integrated with **Supabase (PostgreSQL)** to provide a centralized log for security administrators.
*   **Alert System:** Multi-sensory feedback (Visual Red Alert + Audio Alarm) ensures immediate user awareness.

## 5. System Architecture
(See `algorithm_pipeline.md` for visual reference)
The data flows from a Socket Listener -> Aggregator -> Pre-processor -> AI Engine -> Decision Logic.

## 6. Conclusion
NetGuard demonstrates that effective, enterprise-grade intrusion detection can be implemented on resource-constrained mobile devices using modern edge-computing techniques. It bridges the gap between complex server-side IDPS and simple mobile firewalls.
