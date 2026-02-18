[app]
title = NetGuard IDPS
package.name = netguardidps
package.domain = com.muhammadibrahim.netguard
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json
source.include_patterns = assets/*

# EXCLUSIONS - Minimize redundant files
source.exclude_dirs = tests, logs, viva_docs, docs, .venv, .git, .gradle, .vscode, __pycache__, Android_Build_OneClick
source.exclude_patterns = *.md, *.log, *.txt, *.bat, *.ps1, setup.py, setup_supabase.py, attack_script.py, test_*.py, check_*.py, debug_*.py, NetGuard.zip*

version = 1.0.1
requirements = python3,kivy==2.3.0,kivymd==1.2.0,pillow,pyjnius,requests,charset-normalizer,idna,urllib3

orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,BIND_VPN_SERVICE,FOREGROUND_SERVICE,POST_NOTIFICATIONS,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,PACKAGE_USAGE_STATS,SYSTEM_ALERT_WINDOW

android.api = 34
android.minapi = 24
android.sdk = 34
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a
android.use_androidx = True
android.allow_backup = False

# Colab Specific 
# Forces buildozer to not ask for licenses interactively
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
