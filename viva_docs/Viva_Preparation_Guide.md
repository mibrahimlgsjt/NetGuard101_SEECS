# NetGuard Viva Preparation Guide

Use this document to prepare for your project defense. It covers the core narrative, technical explanations, and answers to likely questions.

## 1. The "Elevator Pitch" (30 Seconds)
"NetGuard is an AI-powered Intrusion Detection and Prevention System (IDPS) designed for Android devices. Unlike traditional firewalls that rely solely on static rules, NetGuard uses a hybrid approach: it combines rule-based filtering with a lightweight TensorFlow Lite model to detect anomaly-based threats in real-time. It features a modern KivyMD interface for monitoring and syncs all threat data to Supabase for remote auditing."

## 2. Key Technical Concepts to Explain

### The Hybrid Detection Engine
*   **Layer 1 (Static):** Immediate blocking of banned IPs (Blacklisting). fast and efficient.
*   **Layer 2 (AI/Heuristic):** Analyzes packet behavior (Size, Frequency, Port).
    *   *Safe:* Standard HTTP/HTTPS traffic.
    *   *Suspicious:* Non-standard ports or unusual packet sizes.
    *   *Critical:* Potential DOS patterns or known attack signatures.

### Why KivyMD & Python?
*   **Python:** Allows for rapid prototyping of complex logic using libraries like `numpy`.
*   **KivyMD:** Provides a cross-platform (Android/Windows) Material Design UI from a single codebase, crucial for mobile security apps.

### Cloud Sync (Supabase)
*   Offsets storage requirements from the mobile device.
*   Allows a security admin to monitor multiple devices from a central dashboard.
*   Uses asynchronous callbacks to prevent UI freezing during network calls.

## 3. Likely Viva Questions & Answers

**Q: "How accurate is your AI model?"**
**A:** "The model is optimized for mobile performance (TFLite). In our testing context, it achieves high accuracy for the defined threat scenarios (DOS, Probe). However, for a production system, we employ a 'Human-in-the-loop' strategy where the AI flags issues for review rather than automating 100% of blocks to prevent false positives."

**Q: "What happens if the internet goes down? Does protection stop?"**
**A:** "No. The core detection engine runs locally on the device (`on-edge`). Internet is only required for syncing logs to the cloud. The device remains protected even offline."

**Q: "How do you handle real-time traffic without lagging the UI?"**
**A:** "We use threading. The `AcademicSecurityManager` runs traffic analysis in a separate background thread (`threading.Thread`), while the Kivy main thread handles UI updates. This ensures the app remains responsive even under high load."

**Q: "Show me the code where detection happens."**
**A:** Point them to the `AcademicSecurityManager.analyze_traffic()` method in `main.py`. This is where the raw packet data is processed and classified.

**Q: "Can this scale to a large network?"**
**A:** "Currently, it's designed as a Host-based IDPS (HIDPS) for individual mobile devices. For network-wide scaling, we would deploy agents on endpoints and centralize the analysis, using Supabase as the SIEM (Security Information and Event Management) layer."

## 4. Demo Checklist
1.  **Launch App:** Show the dashboard saying "SAFE".
2.  **Start Simulation:** Turn on "Monitoring" and let "Normal" traffic flow.
3.  **Inject Threat:** Run `attack_script.py` in a separate terminal.
4.  **Observe:**
    *   Status card turns **RED**.
    *   Alarm plays.
    *   "Logs" tab updates with the threat.
    *   Supabase dashboard (if open) shows the new entry.
