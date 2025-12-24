# Product Rights & Technical Documentation

## 1. Product Overview
The **AI-powered Intrusion Detection and Prevention System (IDPS)** is a robust, academic-grade security tool designed to monitor network traffic in real-time. It leverages on-device Artificial Intelligence (TFLite) to detect anomalies and malicious patterns that traditional rule-based firewalls might miss. It includes a "Collaborative Defense" mechanism where threats detected by one instance can be reported to a cloud backend (Supabase) to protect all connected users.

## 2. Files Structure
The project follows a modular Python structure:

*   **`main.py`**: The Monolithic Entry Point. Contains the Application Loop, UI Screen definitions (View), and the `AcademicSecurityManager` (Controller/Logic).
*   **`idps/`**: Core logic package.
    *   `cloud_manager.py`: Abstraction layer for Supabase API interactions.
    *   `chat_agent.py`: Module for conversational interfaces (if enabled).
    *   `fsm/`: State machine logic.
*   **`app/assets/`**: Static assets including the trained AI model (`security_model.tflite`).
*   **`setup_supabase.py`**: Systems engineering script for backend database initialization.
*   **`tests/`**: Unit and integration tests.
*   **`logs/`**: Local storage for audit logs (`security_audit.json`).
*   **`buildozer.spec`**: Configuration for compiling the Python app to an Android APK.

## 3. Naming Patterns
- **Files/Modules**: `snake_case` (e.g., `cloud_manager.py`, `main.py`).
- **Classes**: `PascalCase` (e.g., `AcademicSecurityManager`, `DashboardScreen`).
- **Variables/Functions**: `snake_case` (e.g., `analyze_traffic`, `threat_level`).
- **Constants**: `UPPER_CASE` (e.g., `SUPABASE_URL`, `THREAT_LEVEL`).

## 4. UI Design
The User Interface is built with **KivyMD**, following Material Design principles.
*   **Theme**: Dark Mode is the default for a "Hacker/Security" aesthetic.
*   **Navigation**: Bottom Navigation Bar for easy access to primary screens (Dashboard, Logs, Settings).
*   **Components**:
    *   **Dashboard**: Features a prominent "Status Card" that changes color (Green/Orange/Red) based on the system state. Real-time graphs visualize traffic volume.
    *   **Logs**: A filterable list of security events with chips for "All", "Threats", "Suspicious".
    *   **Toasts/Snackbars**: providing immediate feedback for user actions (Login success, Simulation start).

## 5. Key Features & User Flows
*   **Real-time Traffic Monitoring**: Listens to UDP/TCP traffic and analyzes packets on the fly.
*   **AI Inference**: Uses a TFLite deep learning model to score packets with a confidence level.
*   **Collaborative Cloud Defense**:
    *   *Flow*: Threat Detected -> Local Block -> Report IP to Supabase -> Global Ban List Updated -> Other Clients Fetch Ban List.
*   **Traffic Simulation**:
    *   *Flow*: Dashboard -> "Simulate Attack" -> Background Thread generates synthetic malicious packets -> System Reacts.
*   **Auditing**: Comprehensive JSON logging of all events for forensic analysis.

## 6. Backend
The backend is serverless, built on **Supabase** (PostgreSQL).
*   **Auth**: Handles User Sign Up/Login.
*   **Database**:
    *   `threat_intel`: Stores community-reported threats.
    *   `active_bans`: Global blacklist synced to all clients.
    *   `profiles`: User metadata.
*   **Security**: Row Level Security (RLS) ensures only authenticated users can report threats.

## 7. Constraints
*   **Performance**: Packet analysis must happen in <10ms to prevent network lag. Threading is used to offload heavy compute.
*   **Hardware**: TFLite is used to ensure the model runs efficiently on mobile/edge devices without a GPU.
*   **Dependencies**: Requires `kivymd`, `tensorflow` (or tflite-runtime), and `supabase`.

## 8. Security
*   **Local**: The app runs with standard user permissions. Logs are stored locally in the app's verified directory.
*   **Network**: All cloud communication is encrypted via HTTPS/SSL.
*   **Model**: The AI model is included in the package but should be treated as a "Grey Box" - it is probabilistic, not deterministic.
