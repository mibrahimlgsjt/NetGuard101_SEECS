# Product Rights & Technical Documentation

## 1. Product Overview
The **AI-powered Intrusion Detection and Prevention System (IDPS)** is a robust, academic-grade security tool designed to monitor network traffic in real-time. It leverages on-device Artificial Intelligence (TFLite) to detect anomalies and malicious patterns that traditional rule-based firewalls might miss. It includes a "Collaborative Defense" mechanism where threats detected by one instance can be reported to a cloud backend (Supabase) to protect all connected users.

## 2. Files Structure
The project follows a modular Python structure:

*   **`main.py`**: The Monolithic Entry Point. Contains the Application Loop, UI Screen definitions (View), and the `AcademicSecurityManager` (Controller/Logic).
*   **`idps/`**: Core logic package.
    *   `cloud_manager.py`: Abstraction layer for Supabase API interactions.
    *   `fsm/`: State machine logic.
*   **`app/assets/`**: Static assets including the trained AI model (`security_model.tflite`).
*   **`viva_docs/`**: Documentation for academic presentation.
    *   `algorithm_pipeline.md`: Mermaid workflow diagrams.
    *   `Viva_Preparation_Guide.md`: Q&A and defense notes.
    *   `Project_Technical_Summary.md`: Abstract.
    *   `Build_NetGuard_APK.ipynb`: Google Colab notebook for cloud building.
*   **Scripts**:
    *   `quick_start.bat` / `quick_start.py`: Automated PC launcher and dependency installer.
    *   `automate_build.bat`: WSL build automation.
*   **Documentation**:
    *   `How_To_Run_On_Mobile.md`: Android deployment guide.
    *   `How_To_Run_On_PC.md`: Windows/Linux setup guide.

## 3. Naming Patterns
- **Files/Modules**: `snake_case` (e.g., `cloud_manager.py`, `main.py`).
- **Classes**: `PascalCase` (e.g., `AcademicSecurityManager`, `DashboardScreen`).
- **Variables/Functions**: `snake_case` (e.g., `analyze_traffic`, `threat_level`).
- **Constants**: `UPPER_CASE` (e.g., `SUPABASE_URL`, `THREAT_LEVEL`).

## 4. UI Design
The User Interface is built with **KivyMD**, following Material Design principles.
*   **Theme**: Cyber Security Dark Theme (Teal/Cyan accents).
*   **Navigation**: Bottom Navigation Bar (Protection, Apps, Logs, Settings).
*   **Components**:
    *   **Dashboard**: Status Shield (Green/Orange/Red), Active Traffic Graphs.
    *   **Logs**: Filterable timeline of network events.
    *   **Visual Feedback**: Snackbars for alerts, dynamic graphs for analytics.

## 5. Key Features & User Flows
*   **Cross-Platform Execution**: Runs on **Android** (via Buildozer/Colab) and **Windows PC** (via Quick Start).
*   **Real-time Traffic Monitoring**: Listens to UDP/TCP traffic and analyzes packets on the fly.
*   **AI Inference**: Uses a TFLite deep learning model to score packets with a confidence level.
*   **Collaborative Cloud Defense**: Threat Detected -> Local Block -> Report to Supabase -> Global Ban List Updated.
*   **Simulated Testing**: Built-in "Simulate Attack" mode for academic demonstration without live malware.

## 6. Backend
The backend is serverless, built on **Supabase** (PostgreSQL).
*   **Auth**: Handles User Sign Up/Login.
*   **Database**: `threat_intel` (community threats), `active_bans` (global blacklist), `profiles`.
*   **Security**: Row Level Security (RLS) ensures data integrity.

## 7. Constraints & Dependencies
*   **Performance**: Packet analysis <10ms latency target. Threaded architecture.
*   **Key Libraries**:
    *   `kivy`, `kivymd` (UI)
    *   `kivy-gradient` (Visual effects)
    *   `tensorflow` / `tflite-runtime` (AI)
    *   `supabase` (Cloud)
*   **Hardware**: Optimized for Mobile/Edge (No GPU required).

## 8. Deployment Options
### Android (Mobile)
*   **Google Colab**: Cloud-based build using `viva_docs/Build_NetGuard_APK.ipynb` (Recommended).
*   **WSL (Local)**: Requires Ubuntu subsystem. Automated via `automate_build.bat`.

### Windows (PC)
*   **Quick Start**: `quick_start.bat` automates environment checks and launching.
