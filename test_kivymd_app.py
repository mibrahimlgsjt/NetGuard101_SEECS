"""
Quick Test Script for KivyMD IDPS Application
==============================================

This script tests the core components of the IDPS application
without requiring a full UI launch. Useful for CI/CD and debugging.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing imports...")
    
    try:
        from kivy.app import App
        print("✅ Kivy imported successfully")
    except ImportError as e:
        print(f"❌ Kivy import failed: {e}")
        return False
    
    try:
        from kivymd.app import MDApp
        print("✅ KivyMD imported successfully")
    except ImportError as e:
        print(f"❌ KivyMD import failed: {e}")
        return False
    
    try:
        import tensorflow as tf
        print(f"✅ TensorFlow {tf.__version__} imported successfully")
    except ImportError as e:
        print(f"⚠️ TensorFlow not available: {e}")
        print("   Install with: pip install tensorflow")
    
    try:
        import numpy as np
        print(f"✅ NumPy {np.__version__} imported successfully")
    except ImportError as e:
        print(f"❌ NumPy import failed: {e}")
        return False
    
    return True


def test_security_manager():
    """Test AcademicSecurityManager initialization."""
    print("\nTesting AcademicSecurityManager...")
    
    try:
        # Import the manager
        from main import AcademicSecurityManager
        print("✅ AcademicSecurityManager imported")
        
        # Create instance (will fail to load model but should not crash)
        manager = AcademicSecurityManager(model_path="test_model.tflite")
        print("✅ AcademicSecurityManager initialized")
        
        # Test stats
        stats = manager.get_stats()
        print(f"✅ Stats retrieved: {stats}")
        
        # Test callback registration
        def test_callback(threat_level, data):
            print(f"   Callback triggered: Level {threat_level}")
        
        manager.register_callback(test_callback)
        print("✅ Callback registered")
        
        return True
    except Exception as e:
        print(f"❌ AcademicSecurityManager test failed: {e}")
        return False


def test_screen_classes():
    """Test that screen classes can be instantiated."""
    print("\nTesting Screen Classes...")
    
    try:
        from main import DashboardScreen, NetworkLogsScreen, SettingsScreen
        print("✅ All screen classes imported successfully")
        return True
    except Exception as e:
        print(f"❌ Screen class import failed: {e}")
        return False


def test_app_class():
    """Test that main app class can be imported."""
    print("\nTesting IDPSApp Class...")
    
    try:
        from main import IDPSApp
        print("✅ IDPSApp class imported successfully")
        return True
    except Exception as e:
        print(f"❌ IDPSApp import failed: {e}")
        return False


def test_kv_string():
    """Test that KV string is valid."""
    print("\nTesting KV String...")
    
    try:
        from main import KV_STRING
        
        # Basic validation
        required_elements = [
            'MDNavigationLayout',
            'ScreenManager',
            'MDBottomNavigation',
            'DashboardScreen',
            'NetworkLogsScreen',
            'SettingsScreen'
        ]
        
        for element in required_elements:
            if element in KV_STRING:
                print(f"✅ Found {element} in KV string")
            else:
                print(f"❌ Missing {element} in KV string")
                return False
        
        return True
    except Exception as e:
        print(f"❌ KV string test failed: {e}")
        return False


def run_all_tests():
    """Run all tests and report results."""
    print("=" * 60)
    print("KivyMD IDPS Application - Component Tests")
    print("=" * 60)
    
    tests = [
        ("Import Test", test_imports),
        ("Security Manager Test", test_security_manager),
        ("Screen Classes Test", test_screen_classes),
        ("App Class Test", test_app_class),
        ("KV String Test", test_kv_string)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ {test_name} crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:.<40} {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! App is ready to run.")
        print("\nTo start the app:")
        print("  python main.py")
        return 0
    else:
        print("\n⚠️ Some tests failed. Please install missing dependencies:")
        print("  pip install -r requirements-kivymd.txt")
        return 1


if __name__ == '__main__':
    exit_code = run_all_tests()
    sys.exit(exit_code)

