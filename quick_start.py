#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Start Script for KivyMD IDPS Application
==============================================

This script helps you set up and run the IDPS application quickly.
It checks dependencies, installs missing packages, and launches the app.

Usage (Windows):
    python quick_start.py           # Run with GUI
    python quick_start.py --test    # Run tests only
    python quick_start.py --setup   # Setup dependencies only

Usage (Linux/Mac):
    ./quick_start.py                # Run with GUI
    python3 quick_start.py --test   # Run tests only
"""

import sys
import subprocess
import os
import argparse


def print_banner():
    """Print welcome banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    🛡️  NetGuard101_SEECS - AI-Powered Intrusion Detection System      ║
║                   KivyMD Edition                          ║
║                                                           ║
║    Industry-Grade Security Monitoring                    ║
║    Powered by TensorFlow Lite                            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def check_python_version():
    """Check if Python version is compatible."""
    print("🔍 Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print(f"❌ Python 3.9+ required. Current version: {version.major}.{version.minor}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
    return True


def check_package(package_name, import_name=None):
    """Check if a package is installed."""
    if import_name is None:
        import_name = package_name
    
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def install_package(package_name):
    """Install a package using pip."""
    print(f"📦 Installing {package_name}...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", package_name, "--quiet"
        ])
        print(f"✅ {package_name} installed")
        return True
    except subprocess.CalledProcessError:
        print(f"❌ Failed to install {package_name}")
        return False


def setup_dependencies():
    """Install all required dependencies."""
    print("\n🔧 Setting up dependencies...\n")
    
    dependencies = [
        ("kivy", "kivy"),
        ("kivymd", "kivymd"),
        ("tensorflow", "tensorflow"),
        ("numpy", "numpy"),
        ("pillow", "PIL"),
    ]
    
    missing = []
    for package_name, import_name in dependencies:
        if check_package(package_name, import_name):
            print(f"✅ {package_name} already installed")
        else:
            print(f"⚠️ {package_name} not found")
            missing.append(package_name)
    
    if missing:
        print(f"\n📋 Installing {len(missing)} missing package(s)...\n")
        
        # Install from requirements file if it exists
        if os.path.exists("requirements-kivymd.txt"):
            print("📄 Installing from requirements-kivymd.txt...")
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", 
                    "-r", "requirements-kivymd.txt"
                ])
                print("✅ All dependencies installed")
                return True
            except subprocess.CalledProcessError:
                print("⚠️ Requirements file installation failed, trying individual packages...")
        
        # Install individually
        success = True
        for package in missing:
            if not install_package(package):
                success = False
        
        return success
    else:
        print("\n✅ All dependencies are already installed")
        return True


def run_tests():
    """Run component tests."""
    print("\n🧪 Running component tests...\n")
    
    if not os.path.exists("test_kivymd_app.py"):
        print("⚠️ Test file not found: test_kivymd_app.py")
        return False
    
    try:
        result = subprocess.call([sys.executable, "test_kivymd_app.py"])
        return result == 0
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


def check_model_file():
    """Check if TFLite model exists."""
    model_path = "app/assets/security_model.tflite"
    
    if os.path.exists(model_path):
        size_mb = os.path.getsize(model_path) / (1024 * 1024)
        print(f"✅ TFLite model found: {model_path} ({size_mb:.2f} MB)")
        return True
    else:
        print(f"⚠️ TFLite model not found: {model_path}")
        print("   The app will run but threat detection will be simulated.")
        print("   Place your trained model at: app/assets/security_model.tflite")
        return False


def run_app(demo_mode=False):
    """Launch the IDPS application."""
    print(f"\n🚀 Launching IDPS application{' (DEMO MODE)' if demo_mode else ''}...\n")
    
    if not os.path.exists("main.py"):
        print("❌ main.py not found in current directory")
        return False
    
    try:
        # Set environment variable for better graphics on some systems
        os.environ['KIVY_GL_BACKEND'] = 'angle_sdl2'
        
        # Run the app
        cmd = [sys.executable, "main.py"]
        if demo_mode:
            cmd.append("--demo")
            
        subprocess.call(cmd)
        return True
    except KeyboardInterrupt:
        print("\n\n⏹️ Application stopped by user")
        return True
    except Exception as e:
        print(f"❌ Failed to launch app: {e}")
        return False


def print_help():
    """Print help information."""
    help_text = """
📚 QUICK START GUIDE
═══════════════════

DESKTOP TESTING:
  python quick_start.py              Run the app
  python quick_start.py --test       Run tests only
  python quick_start.py --setup      Install dependencies only

ANDROID BUILD:
  1. Install buildozer:
     pip install buildozer
  
  2. Build APK:
     buildozer android debug
  
  3. Deploy to device:
     buildozer android debug deploy run

MANUAL RUN:
  python main.py

REQUIREMENTS:
  - Python 3.9+
  - Kivy, KivyMD, TensorFlow, NumPy, Pillow
  - See requirements-kivymd.txt for full list

TROUBLESHOOTING:
  - TensorFlow issues: pip install tensorflow --upgrade
  - Kivy graphics issues: Set KIVY_GL_BACKEND=angle_sdl2
  - Permission errors: Run as administrator/sudo

DOCUMENTATION:
  - KIVYMD_APP_GUIDE.md - Complete user guide
  - KIVYMD_ARCHITECTURE.md - Technical architecture
  - README.md - Project overview

SUPPORT:
  - GitHub: [Your repo URL]
  - Documentation: docs/
  - Issues: [Your issues URL]
"""
    print(help_text)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Quick start script for IDPS KivyMD application"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run component tests only"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Install dependencies only"
    )
    parser.add_argument(
        "--help-guide",
        action="store_true",
        help="Show detailed help guide"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run application in Demo Mode"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    # Show help guide
    if args.help_guide:
        print_help()
        return 0
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Setup dependencies
    print()
    if not setup_dependencies():
        print("\n❌ Dependency setup failed")
        print("   Try installing manually:")
        print("   pip install -r requirements-kivymd.txt")
        return 1
    
    # Check for model file
    print()
    check_model_file()
    
    # Run tests if requested
    if args.test:
        print()
        if run_tests():
            print("\n✅ All tests passed!")
            return 0
        else:
            print("\n❌ Some tests failed")
            return 1
    
    # Setup only mode
    if args.setup:
        print("\n✅ Setup complete!")
        print("   Run 'python main.py' to start the app")
        return 0
    
    # Run the app
    if run_app(demo_mode=args.demo):
        print("\n👋 Thanks for using IDPS!")
        return 0
    else:
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⏹️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

