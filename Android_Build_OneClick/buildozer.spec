[app]

# (str) Title of your application
title = IDPS NetGuard

# (str) Package name
package.name = idpsnetguard

# (str) Package domain (needed for android/ios packaging)
package.domain = com.idps

# (str) Source code where the main.py live
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,kv,atlas,tflite

# (list) Source files to include by pattern
source.include_patterns = assets/*

# (str) Application versioning (method 1)
version = 1.0.0

# (list) Application requirements
# Academic-grade libraries for secure Android build with KivyMD
requirements = python3,kivy,kivymd,pillow,tensorflow,numpy,cryptography>=41.0.0,pydantic>=2.5.0,httpx>=0.25.0,certifi>=2023.11.17,urllib3>=2.1.0,pyjnius

# (str) Supported orientation (one of landscape, sensorLandscape, portrait or all)
orientation = portrait

#
# Android specific
#

# (str) Android SDK path (or set ANDROID_SDK environment variable)
# Default: Uses ANDROID_SDK environment variable or auto-detects
# For explicit path, uncomment and set:
# android.sdk_path = C:/Users/Admin/AppData/Local/Android/Sdk

# (str) Java JDK path (or set JAVA_HOME environment variable)
# Required: Java 17 (JDK-17) for Android builds
# Default: Uses JAVA_HOME environment variable or auto-detects
# For explicit path, uncomment and set (example paths):
# android.jdk_path = C:/Program Files/Java/jdk-17
# Or: android.jdk_path = C:/Program Files/Java/jdk-17.0.x

# (bool) Indicate if the application should be fullscreen or not
fullscreen = 0

# (list) Permissions
android.permissions = INTERNET,ACCESS_NETWORK_STATE,BIND_VPN_SERVICE,FOREGROUND_SERVICE,POST_NOTIFICATIONS,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,PACKAGE_USAGE_STATS,SYSTEM_ALERT_WINDOW

# (list) The Android archs to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
android.archs = arm64-v8a, armeabi-v7a

# (int) Target Android API, should be as high as possible.
android.api = 34

# (int) Minimum API your APK / AAB will support.
android.minapi = 24

# (bool) Use AndroidX support libraries
android.use_androidx = True

# (bool) enables Android auto backup feature (Android API >=23)
# SECURITY: Set to False to prevent unauthorized data backup
android.allow_backup = False

# (str) The format used to package the app for release mode (aab or apk).
# android.release_artifact = aab

# (str) The format used to package the app for debug mode (apk or aab).
# android.debug_artifact = apk

#
# Python for android (p4a) specific
#

# (int) The maximum number of concurrent jobs
p4a.max_build_jobs = 1

