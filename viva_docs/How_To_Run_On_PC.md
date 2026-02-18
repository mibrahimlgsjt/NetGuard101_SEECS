# How to Run NetGuard on PC (Windows)

The project includes an automation script that handles dependency installation and launches the application for you.

## 🚀 The Fastest Way (Automatic)

1.  **Open the Folder**: Navigate to your project folder: `c:\Users\Admin\Desktop\NetGuard proj`
2.  **Run Quick Start**: Double-click the file named **`quick_start.bat`**.

**What this script does:**
*   Checks if Python is installed.
*   Automatically installs required libraries (`kivy`, `kivymd`, `tensorflow`, etc.).
*   Launches the **NetGuard IDPS Dashboard**.

---

## 🛠️ Manual Method (Command Line)

If you prefer to run it via PowerShell or Command Prompt:

1.  **Open PowerShell** in the project directory.
2.  **Install Dependencies**:
    ```powershell
    pip install -r requirements-kivymd.txt
    ```
3.  **Run the App**:
    ```powershell
    python main.py
    ```

---

## 💻 System Requirements
*   **Python 3.9+**: If not installed, get it from [python.org](https://www.python.org/).
*   **Internet Connection**: Required only for the first run to download the libraries.

## 📁 Where are the logs?
When running on PC, security logs are saved in the `logs/` folder within the project directory.
