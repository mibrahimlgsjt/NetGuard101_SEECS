# 🛡️ Firewall AI: Intelligent Mobile Security

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Python](https://img.shields.io/badge/python-3.8%2B-yellow.svg) ![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Windows-green.svg) ![Status](https://img.shields.io/badge/status-Active-success.svg)

**Firewall AI** (formerly IDPS) is a next-generation mobile security application that brings academic-grade Intrusion Detection and Prevention capabilities to Android devices. It features a stunning Dark/Gold premium interface, real-time data monitoring, and an AI-powered threat engine.

## 🚀 Key Features

- **🧠 AI Threat Engine**: Detects zero-day attacks and anomalies using advanced machine learning models (TensorFlow Lite).
- **🛡️ Active Shield**: Visual, pulsing dashboard indicator showing real-time system status.
- **📱 Smart App Firewall**: Monitor and block suspicious applications with a single tap.
- **📊 Data Usage Monitor**: Real-time tracking of Mobile and Wi-Fi data consumption (RX/TX).
- **📋 Traffic Logs**: Detailed event logging with graphical visualizations of weekly trends.
- **🎮 Smart Demo Mode**: Intelligent simulation for testing on desktop environments without Android hardware.

## 📸 Screenshots

| Dashboard | App Firewall | Logs |
|:---:|:---:|:---:|
| *(Shield UI)* | *(App List)* | *(Traffic Stats)* |

## 🛠️ Tech Stack

- **Language**: Python 3
- **UI Framework**: Kivy & KivyMD (Material Design 3)
- **AI/ML**: TensorFlow / Scikit-learn (Logic embedded)
- **Android Bridge**: Pyjnius (JNI for Android API access)
- **Build Tool**: Buildozer

## 📦 Installation & Usage

### Prerequisites
- Python 3.8+
- Kivy & KivyMD
- Pyjnius (for Android features)

### Running on Windows (Demo Mode)
1. Clone the repository:
   ```bash
   git clone https://github.com/mibrahimlgsjt/NetGuard101_SEECS.git
   cd NetGuard101_SEECS
   ```
2. Install dependencies:
   ```bash
   pip install kivymd kivy
   ```
3. Run the application:
   ```bash
   python main.py
   ```
   *The app will automatically launch in **Smart Demo Mode**, simulating network traffic and app activity.*

### Building for Android
1. Ensure you have `buildozer` installed on a Linux/WSL environment.
2. Connect your Android device.
3. Build and deploy:
   ```bash
   buildozer android debug deploy run
   ```

## 📂 Project Structure

- `main.py`: Core application logic and UI layout (KV).
- `android_utils.py`: Bridge to Android native APIs (TrafficStats, UsageStats).
- `demo_mode.py`: Mock data generator for desktop testing.
- `buildozer.spec`: Android build configuration profile.

## 🔒 Security

This project implements **Academic-Grade Security Standards**:
- **Privacy First**: All logs are stored locally.
- **Secure Storage**: Sensitive configuration is isolated.
- **Low Footprint**: Optimized for battery life and performance.

---
*Created by [Your Name/Team] for SEECS.*
