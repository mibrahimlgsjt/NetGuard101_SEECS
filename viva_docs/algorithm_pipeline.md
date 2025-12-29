# NetGuard IDPS Algorithm Pipeline

This diagram illustrates the flow of data through the NetGuard Intrusion Detection and Prevention System, from traffic ingress to threat mitigation and reporting.

```mermaid
flowchart TD
    subgraph Input_Layer ["Input Layer"]
        A["Real Traffic / Attack Script"] -->|UDP Packets| B("Socket Listener")
        C["Simulation Mode"] -->|"Generated Data"| D("Traffic Generator")
    end

    subgraph Core_Processing ["Core Processing Unit"]
        B --> E{"Traffic Aggregator"}
        D --> E
        E --> F["Preprocessing & Rule Engine"]
        
        F -->|"Check IP Blacklist"| G{"Is Banned?"}
        G -- "Yes" --> H["Immediate Block"]
        G -- "No" --> I["Feature Extraction"]
    end

    subgraph AI_Analysis ["AI Analysis Engine"]
        I --> J{"Model Available?"}
        J -- "Yes" --> K["TFLite Inference"]
        J -- "No" --> L["Heuristic / Rule-Based Logic"]
        
        K --> M["Threat Classification"]
        L --> M
    end

    subgraph Response_Layer ["Response & Action"]
        H --> N["Log Event"]
        M -- "Safe (0)" --> O["Update Traffic Stats"]
        M -- "Suspicious (1)" --> P["Trigger Warning UI"]
        M -- "Critical (2)" --> Q["Trigger Alarm Sound"]
        
        Q --> R["Log Threat Event"]
        P --> N
        R --> N
    end

    subgraph Cloud_Integration ["Cloud Sync"]
        N --> S[("Supabase Cloud DB")]
        O --> S
    end

    style Input_Layer fill:#e3f2fd,stroke:#1565c0
    style Core_Processing fill:#f3e5f5,stroke:#7b1fa2
    style AI_Analysis fill:#e8f5e9,stroke:#2e7d32
    style Response_Layer fill:#fff3e0,stroke:#ef6c00
    style Cloud_Integration fill:#eceff1,stroke:#455a64
```

## Description of Stages

1.  **Input Layer**: System accepts traffic from either real-world network sockets (listening for packets from `attack_script.py`) or an internal simulation engine for demonstration.
2.  **Core Processing**:
    *   **Aggregator**: Unifies data streams.
    *   **Rule Engine**: Checks against static rules (e.g., known bad IPs) for immediate blocking.
3.  **AI Analysis**:
    *   **Feature Extraction**: Parses packet metadata (Size, Port, Protocol).
    *   **Inference**: Uses a lightweight TensorFlow Lite model to predict threat levels. Falls back to robust heuristics if the model is unavailable.
4.  **Response Layer**:
    *   **Safe**: Updates normal traffic counters.
    *   **Suspicious**: Alerts the user visually.
    *   **Critical**: Triggers an audible alarm and logs the incident as a high-priority threat.
5.  **Cloud Integration**: Asynchronously pushes logs and stats to Supabase for remote monitoring and historical auditing.
