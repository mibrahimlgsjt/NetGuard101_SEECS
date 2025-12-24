# Android Build Configuration - Secure IDPS APK

## Overview

This document explains the secure Android build configuration for the AI-powered Intrusion Detection and Prevention System (IDPS). The build system is configured with academic-grade libraries and hardened security flags.

## Academic-Grade Libraries

The following production-ready libraries are configured in `setup.py` and `requirements.txt`:

### 1. **cryptography** (>=41.0.0)
- **Purpose**: Industry-standard encryption and security primitives
- **Features**: 
  - Modern cipher support (AES-256, ChaCha20-Poly1305)
  - X.509 certificate handling
  - Key derivation functions (PBKDF2, scrypt, Argon2)
- **Use Case**: Encrypting sensitive IDPS data, secure key storage

### 2. **pydantic** (>=2.5.0)
- **Purpose**: Runtime data validation and schema enforcement
- **Features**:
  - V2 with improved performance (Rust-based validation)
  - Type coercion and validation
  - JSON schema generation
- **Use Case**: Validating network packet schemas, API request/response validation

### 3. **httpx** (>=0.25.0)
- **Purpose**: Modern async HTTP client with TLS 1.3 support
- **Features**:
  - HTTP/2 and HTTP/3 support
  - Modern TLS (1.2, 1.3) enforcement
  - Async/await support
  - Certificate pinning
- **Use Case**: Secure API communication, threat intelligence feeds

### 4. **certifi** (>=2023.11.17)
- **Purpose**: Mozilla CA bundle for TLS verification
- **Use Case**: Ensuring valid SSL/TLS certificate chains

### 5. **urllib3** (>=2.1.0)
- **Purpose**: HTTP library with security fixes
- **Use Case**: Low-level HTTP operations with security patches

## Android Security Flags

### Manifest-Level Security

The `AndroidManifest.xml` includes critical security flags:

#### 1. `android:allowBackup="false"`
- **Location**: `<application>` tag
- **Purpose**: Prevents unauthorized data extraction via Android backup mechanisms
- **Security Impact**: 
  - Blocks `adb backup` commands from extracting app data
  - Prevents backup apps from accessing sensitive IDPS data
  - Protects against data exfiltration attacks

#### 2. `android:usesCleartextTraffic="false"`
- **Location**: `<application>` tag
- **Purpose**: Enforces HTTPS/TLS-only network communication
- **Security Impact**:
  - Blocks all HTTP (non-encrypted) traffic
  - Forces all network requests to use TLS 1.2+
  - Prevents man-in-the-middle attacks on unencrypted connections

#### 3. `android:networkSecurityConfig`
- **Location**: `<application>` tag
- **Purpose**: References custom network security configuration
- **File**: `app/src/main/res/xml/network_security_config.xml`
- **Security Impact**:
  - Enforces TLS 1.2+ minimum
  - Blocks cleartext traffic globally
  - Allows domain-specific certificate pinning

## Build Configuration Files

### 1. `setup.py`
- **Purpose**: Python package configuration and Android build setup script
- **Usage**: 
  ```bash
  python setup.py  # Runs Android build configuration
  pip install -e .  # Installs package with dependencies
  ```
- **Features**:
  - Auto-generates AndroidManifest.xml with security flags
  - Creates network security config
  - Sets up VS Code configuration
  - Configures Gradle properties

### 2. `requirements.txt`
- **Purpose**: Python dependencies list
- **Usage**: `pip install -r requirements.txt`
- **Contains**: All academic-grade libraries with version constraints

### 3. `app/build.gradle`
- **Purpose**: Android Gradle build configuration
- **Features**:
  - Java 17 compatibility
  - ProGuard/R8 code obfuscation for release builds
  - Security library dependencies
  - Multi-ABI support (ARM, x86)

### 4. `buildozer.spec`
- **Purpose**: Buildozer configuration for Python-to-Android builds
- **Usage**: `buildozer android debug` or `buildozer android release`
- **Security Settings**:
  - `android.allow_backup = False` (matches manifest flag)
  - Minimum API 24 (Android 7.0+)
  - Target API 34 (Android 14)

## Build Process

### Option 1: Using Buildozer (Python-to-Android)

1. **Install Buildozer**:
   ```bash
   pip install buildozer
   ```

2. **Configure**:
   ```bash
   python setup.py  # Generate Android manifest and configs
   ```

3. **Build APK**:
   ```bash
   buildozer android debug   # Debug build
   buildozer android release # Release build (requires signing)
   ```

### Option 2: Using Android Studio/Gradle

1. **Setup**:
   ```bash
   python setup.py  # Generate manifest and configs
   ```

2. **Open in Android Studio**:
   - Import project
   - Sync Gradle
   - Build → Build Bundle(s) / APK(s)

3. **Security Verification**:
   - Check `app/src/main/AndroidManifest.xml` for security flags
   - Verify `app/src/main/res/xml/network_security_config.xml` exists

## Security Verification Checklist

- [ ] `android:allowBackup="false"` is set in AndroidManifest.xml
- [ ] `android:usesCleartextTraffic="false"` is set in AndroidManifest.xml
- [ ] `network_security_config.xml` exists and blocks cleartext traffic
- [ ] All academic libraries are installed (`pip install -r requirements.txt`)
- [ ] Release builds have ProGuard/R8 enabled
- [ ] Debug builds are not distributed
- [ ] APK signing is configured for release builds

## Manifest Injection Details

The security flags are automatically injected into `AndroidManifest.xml` when you run:

```bash
python setup.py
```

The generated manifest will be located at:
```
app/src/main/AndroidManifest.xml
```

### Manual Verification

To verify the security flags are present:

```bash
# Windows PowerShell
Select-String -Path "app\src\main\AndroidManifest.xml" -Pattern "allowBackup|usesCleartextTraffic"

# Linux/Mac
grep -E "allowBackup|usesCleartextTraffic" app/src/main/AndroidManifest.xml
```

Expected output:
```xml
android:allowBackup="false"
android:usesCleartextTraffic="false"
```

## Network Security Configuration

The `network_security_config.xml` enforces:

1. **Global Cleartext Block**: All HTTP traffic is blocked
2. **TLS Enforcement**: Only TLS 1.2+ connections allowed
3. **Certificate Validation**: System and user certificates trusted
4. **Domain-Specific Rules**: Can be customized for specific APIs

## Troubleshooting

### Issue: Build fails with "usesCleartextTraffic not recognized"
- **Solution**: Ensure `android:networkSecurityConfig` is set and the XML file exists

### Issue: Libraries not found during build
- **Solution**: Run `pip install -r requirements.txt` before building

### Issue: Manifest not generated
- **Solution**: Run `python setup.py` to generate Android manifest structure

## References

- [Android Security Best Practices](https://developer.android.com/training/best-security)
- [Network Security Config](https://developer.android.com/training/articles/security-config)
- [Cryptography Library Docs](https://cryptography.io/)
- [Pydantic V2 Docs](https://docs.pydantic.dev/)
- [HTTPX Documentation](https://www.python-httpx.org/)

