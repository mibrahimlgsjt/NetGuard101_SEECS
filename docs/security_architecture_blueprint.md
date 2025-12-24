# Security Architecture Blueprint
## CIA Triad & AAA Model Implementation

**Project**: AI-powered Intrusion Detection and Prevention System (IDPS)  
**Phase**: 1 - Security Architecture  
**Date**: 2024

---

## Executive Summary

This document outlines the security architecture for the IDPS Android application, implementing the **Confidentiality, Integrity, and Availability (CIA) Triad** alongside the **Authentication, Authorization, and Accounting (AAA) Model**. The architecture ensures defense-in-depth through multiple security layers.

---

## 1. CIA Triad Implementation

### 1.1 Confidentiality

**Principle**: Protect data from unauthorized access.

#### 1.1.1 Data-at-Rest Encryption
- **Technology**: AES-256-GCM (Galois/Counter Mode)
- **Storage**: Encrypted SQLite database using SQLCipher wrapper
- **Key Management**: Android Keystore System (hardware-backed when available)
- **Scope**: All sensitive data including:
  - User credentials (hashed, never plaintext)
  - Network traffic logs
  - Intrusion detection rules
  - System configuration
  - Audit logs

#### 1.1.2 Data-in-Transit Encryption
- **Technology**: RSA-4096 for key exchange, AES-256-GCM for symmetric encryption
- **Protocol**: TLS 1.3 minimum
- **Certificate Pinning**: Implement certificate pinning for API endpoints
- **Scope**: All network communications:
  - API requests/responses
  - Real-time threat intelligence feeds
  - Remote logging (if enabled)
  - Configuration synchronization

#### 1.1.3 Least Privilege Principle
- **Database Access**: Role-based table-level permissions
- **File System**: Sandboxed app storage, no access to external storage without explicit user permission
- **Network**: Minimal required permissions, no unnecessary network access
- **System Resources**: Resource quotas and limits per user role

---

### 1.2 Integrity

**Principle**: Ensure data has not been tampered with or corrupted.

#### 1.2.1 Data Integrity Verification
- **Technology**: HMAC-SHA256 (Hash-based Message Authentication Code)
- **Implementation**: Every database record includes:
  - `record_id`: Unique identifier
  - `data`: Encrypted payload
  - `hmac`: HMAC-SHA256(data + record_id + timestamp)
  - `timestamp`: Record creation/modification time
  - `version`: Record version number (for conflict resolution)

#### 1.2.2 Integrity Validation Service
- **Real-time Validation**: Validate HMAC on every read operation
- **Batch Validation**: Periodic integrity checks on all records
- **Tamper Detection**: Alert system when integrity check fails
- **Recovery**: Automatic rollback to last known good state

#### 1.2.3 Code Integrity
- **APK Signing**: Strong app signing with Play App Signing
- **Runtime Checks**: Verify app signature integrity at runtime
- **Library Verification**: Validate third-party library checksums

---

### 1.3 Availability

**Principle**: Ensure system remains accessible and functional.

#### 1.3.1 Graceful Degradation Model
- **Offline Mode**: Full functionality using local cache
- **Cache Strategy**: 
  - LRU (Least Recently Used) cache for frequently accessed data
  - Time-based cache expiration
  - Pre-fetching of critical data when online
- **Fallback Mechanisms**:
  - Local rule engine when cloud updates unavailable
  - Cached threat intelligence database
  - Offline logging with sync when connection restored

#### 1.3.2 Redundancy & Resilience
- **Database Backups**: Encrypted backups stored securely
- **Connection Retry**: Exponential backoff for network failures
- **Resource Management**: Memory and CPU usage limits to prevent crashes
- **Error Handling**: Comprehensive error handling with user-friendly messages

---

## 2. AAA Model Implementation

### 2.1 Authentication

**Principle**: Verify user identity before granting access.

#### 2.1.1 Multi-Factor Authentication (MFA)
- **Primary**: Biometric authentication (Fingerprint/Face ID)
- **Secondary**: PIN/Password (encrypted storage)
- **Fallback**: Recovery codes (encrypted, one-time use)

#### 2.1.2 Authentication Flow
1. User launches app
2. Biometric prompt (Android BiometricPrompt API)
3. On success: Decrypt master key from Android Keystore
4. On failure: Fallback to PIN/Password (limited attempts)
5. Session token generation (JWT with short expiration)
6. Session management with automatic timeout

#### 2.1.3 Session Management
- **Token Type**: JWT (JSON Web Token)
- **Expiration**: 15 minutes of inactivity
- **Refresh Tokens**: Long-lived refresh tokens (encrypted storage)
- **Device Binding**: Token tied to device ID and app instance

---

### 2.2 Authorization

**Principle**: Control what authenticated users can access and do.

#### 2.2.1 Role-Based Access Control (RBAC)

**Role Hierarchy**:
```
SuperAdmin (Level 4)
    ├── Admin (Level 3)
    │   ├── SecurityAnalyst (Level 2)
    │   │   └── User (Level 1)
```

**Role Definitions**:

1. **User (Level 1)**
   - View own security status
   - View own threat alerts
   - Basic app configuration
   - No access to system logs or admin functions

2. **SecurityAnalyst (Level 2)**
   - All User permissions
   - View detailed threat logs
   - Create custom detection rules (local only)
   - Export reports
   - View network traffic summaries

3. **Admin (Level 3)**
   - All SecurityAnalyst permissions
   - Manage users and roles
   - Configure system-wide settings
   - Access audit logs
   - Manage encryption keys (with approval workflow)

4. **SuperAdmin (Level 4)**
   - All Admin permissions
   - Full system access
   - Key recovery operations
   - System backup/restore
   - Emergency access procedures

#### 2.2.2 Permission Matrix

| Resource | User | SecurityAnalyst | Admin | SuperAdmin |
|----------|------|-----------------|-------|------------|
| View own alerts | ✓ | ✓ | ✓ | ✓ |
| View all alerts | ✗ | ✓ | ✓ | ✓ |
| Create rules | ✗ | ✓ (local) | ✓ | ✓ |
| Delete rules | ✗ | ✗ | ✓ | ✓ |
| User management | ✗ | ✗ | ✓ | ✓ |
| Key management | ✗ | ✗ | ✓ (with approval) | ✓ |
| Audit logs | ✗ | ✗ | ✓ | ✓ |
| System backup | ✗ | ✗ | ✗ | ✓ |

#### 2.2.3 Attribute-Based Access Control (ABAC) Extensions
- **Time-based**: Certain operations only during business hours
- **Location-based**: Restrict sensitive operations to trusted locations
- **Device-based**: Only allow admin functions from registered devices

---

### 2.3 Accounting

**Principle**: Track and log all user activities for audit and compliance.

#### 2.3.1 Audit Logging
- **Events Logged**:
  - Authentication attempts (success/failure)
  - Authorization decisions (granted/denied)
  - Data access (read/write operations)
  - Configuration changes
  - Security rule modifications
  - Key management operations
  - Export operations
  - Administrative actions

#### 2.3.2 Log Structure
```json
{
  "timestamp": "ISO 8601 format",
  "event_id": "UUID",
  "user_id": "hashed user identifier",
  "role": "user role",
  "action": "action performed",
  "resource": "resource accessed",
  "result": "success/failure",
  "ip_address": "hashed IP",
  "device_id": "hashed device identifier",
  "metadata": {}
}
```

#### 2.3.3 Log Protection
- **Encryption**: All audit logs encrypted at rest (AES-256)
- **Integrity**: HMAC verification for log entries
- **Tamper Resistance**: Append-only log structure
- **Retention**: Configurable retention policy (default: 1 year)
- **Compliance**: GDPR, SOC 2, ISO 27001 compliant logging

---

## 3. Data-at-Rest: Encrypted SQLite Database

### 3.1 SQLCipher Integration Strategy

**Architecture**:
```
Application Layer
    ↓
Security Wrapper Layer (Python/Java Bridge)
    ↓
SQLCipher Wrapper (Native Library)
    ↓
Encrypted SQLite Database
```

**Key Features**:
- **Encryption**: AES-256-CBC (SQLCipher default, upgradeable to AES-256-GCM)
- **Key Derivation**: PBKDF2 with 256,000 iterations
- **Page Size**: 4096 bytes (optimal for Android)
- **Journal Mode**: WAL (Write-Ahead Logging) with encryption

### 3.2 Database Schema Design

**Tables**:
1. **users** (encrypted)
   - user_id (PRIMARY KEY)
   - username (encrypted)
   - password_hash (bcrypt, not encrypted again)
   - role_id (encrypted)
   - created_at, updated_at
   - hmac

2. **threat_logs** (encrypted)
   - log_id (PRIMARY KEY)
   - user_id (encrypted, FOREIGN KEY)
   - threat_type (encrypted)
   - severity (encrypted)
   - details (encrypted JSON)
   - timestamp
   - hmac

3. **detection_rules** (encrypted)
   - rule_id (PRIMARY KEY)
   - rule_name (encrypted)
   - rule_pattern (encrypted)
   - created_by (encrypted, FOREIGN KEY)
   - is_active (encrypted boolean)
   - hmac

4. **audit_logs** (encrypted, append-only)
   - audit_id (PRIMARY KEY)
   - event_data (encrypted JSON)
   - hmac
   - timestamp

5. **session_tokens** (encrypted)
   - token_id (PRIMARY KEY)
   - user_id (encrypted, FOREIGN KEY)
   - token_hash (SHA-256)
   - expires_at
   - hmac

### 3.3 Least Privilege Implementation

**Database Access Control**:
- **Connection-Level**: Each user role gets a separate database connection with limited permissions
- **Table-Level**: Views created for each role, hiding sensitive columns
- **Row-Level**: WHERE clauses filter data based on user_id and role
- **Column-Level**: Sensitive columns encrypted, only decrypted when needed

**Example View for User Role**:
```sql
CREATE VIEW user_threat_logs AS
SELECT 
    log_id,
    threat_type,  -- Decrypted only for this user's records
    severity,
    timestamp
FROM threat_logs
WHERE user_id = CURRENT_USER_ID()
AND hmac_valid = TRUE;
```

---

## 4. Data Integrity: HMAC Service

### 4.1 HMAC Generation Service

**Purpose**: Generate and validate HMAC for every database record to detect tampering.

**Design**:
```
HMACService
├── generateHMAC(data, record_id, timestamp, secret_key)
│   └── Returns: HMAC-SHA256(data + record_id + timestamp + secret_key)
│
├── validateHMAC(record)
│   ├── Extract stored HMAC
│   ├── Recalculate HMAC from record data
│   ├── Compare HMACs
│   └── Returns: Boolean (valid/invalid)
│
├── batchValidate(table_name)
│   └── Validates all records in a table
│
└── repairCorruptedRecord(record_id)
    └── Attempts recovery from backup or marks as corrupted
```

**HMAC Secret Key Management**:
- Stored in Android Keystore (never in plaintext)
- Rotated periodically (every 90 days)
- Separate keys for different data types (users, logs, rules)

### 4.2 Integrity Validation Workflow

**On Read Operation**:
1. Fetch record from database
2. Extract HMAC from record
3. Recalculate HMAC from record data
4. Compare HMACs
5. If mismatch: Log security event, deny access, trigger alert
6. If match: Return decrypted data

**On Write Operation**:
1. Encrypt data
2. Generate HMAC
3. Store record with HMAC
4. Verify HMAC immediately after write
5. Log operation in audit log

**Periodic Validation**:
- Background service runs every 24 hours
- Validates all records in batches
- Reports integrity status to admin dashboard
- Auto-repair minor inconsistencies

---

## 5. Identity Management: Authentication & Authorization

### 5.1 Authentication Class Structure

```
AuthenticationManager
├── BiometricAuthenticator
│   ├── promptBiometric()
│   ├── handleBiometricResult()
│   └── isBiometricAvailable()
│
├── CredentialAuthenticator
│   ├── validatePIN(pin)
│   ├── validatePassword(password)
│   └── handleFailedAttempt()
│
├── SessionManager
│   ├── createSession(user_id)
│   ├── validateSession(token)
│   ├── refreshSession(token)
│   └── destroySession(token)
│
└── RecoveryManager
    ├── generateRecoveryCode(user_id)
    ├── validateRecoveryCode(code)
    └── resetCredentials(user_id, code)
```

**Biometric Authentication Flow**:
1. Check biometric availability (BiometricManager.canAuthenticate())
2. Create BiometricPrompt with crypto object
3. User authenticates with fingerprint/face
4. On success: Unlock Android Keystore key
5. Use key to decrypt master encryption key
6. Create session token
7. Store session (encrypted)

**Credential Fallback**:
- After 3 failed biometric attempts
- PIN/Password prompt (max 5 attempts)
- Account lockout after failed attempts (15 minutes)
- Admin notification on lockout

### 5.2 Authorization Class Structure (RBAC)

```
AuthorizationManager
├── RoleManager
│   ├── assignRole(user_id, role)
│   ├── revokeRole(user_id, role)
│   ├── getUserRoles(user_id)
│   └── hasRole(user_id, role)
│
├── PermissionChecker
│   ├── checkPermission(user_id, resource, action)
│   ├── getEffectivePermissions(user_id)
│   └── isAuthorized(user_id, resource, action)
│
├── ResourceAccessController
│   ├── filterDataByRole(data, user_id)
│   ├── enforceRowLevelSecurity(query, user_id)
│   └── auditAccess(user_id, resource, action, result)
│
└── PolicyEngine
    ├── evaluatePolicy(user, resource, action, context)
    ├── loadPolicies()
    └── updatePolicy(policy_id, new_policy)
```

**RBAC Implementation**:
- **Role Inheritance**: Child roles inherit parent permissions
- **Permission Override**: Explicit deny overrides allow
- **Dynamic Permissions**: Permissions can be granted temporarily
- **Context-Aware**: Time, location, device factors considered

**Example Permission Check**:
```python
def checkPermission(user_id, resource, action):
    user_roles = getUserRoles(user_id)
    for role in user_roles:
        if role.hasPermission(resource, action):
            context = getContext()  # time, location, device
            if evaluatePolicy(role, resource, action, context):
                auditAccess(user_id, resource, action, "granted")
                return True
    auditAccess(user_id, resource, action, "denied")
    return False
```

---

## 6. Key Management: Android Keystore System

### 6.1 Key Storage Strategy

**Android Keystore Integration**:
- **Purpose**: Store cryptographic keys securely, never in plaintext in RAM
- **Hardware Security Module (HSM)**: Use hardware-backed keystore when available
- **Key Types**: 
  - AES keys (for data encryption)
  - RSA keys (for data-in-transit)
  - HMAC keys (for integrity verification)

### 6.2 Key Hierarchy

```
Master Key (Android Keystore)
├── Database Encryption Key (AES-256)
│   ├── Users Table Key
│   ├── Logs Table Key
│   └── Rules Table Key
│
├── HMAC Secret Keys
│   ├── Users HMAC Key
│   ├── Logs HMAC Key
│   └── Rules HMAC Key
│
├── RSA Key Pair (4096-bit)
│   ├── Public Key (for TLS)
│   └── Private Key (Android Keystore)
│
└── Session Token Key (AES-256)
```

### 6.3 Key Lifecycle Management

**Key Generation**:
1. Generate key in Android Keystore (hardware-backed if available)
2. Set key attributes:
   - `setUserAuthenticationRequired(true)` - Requires biometric
   - `setUserAuthenticationValidityDurationSeconds(900)` - 15 min timeout
   - `setEncryptionPaddings(ENCRYPTION_PADDING_RSA_OAEP)`
3. Store key alias securely
4. Never export private key material

**Key Access**:
- Keys accessed only through Android Keystore API
- Biometric authentication required to unlock keystore
- Keys never leave secure hardware (when HSM available)
- Key material never exposed to application code

**Key Rotation**:
- **Database Keys**: Rotate every 90 days
- **HMAC Keys**: Rotate every 90 days (with overlap period)
- **RSA Keys**: Rotate every 365 days
- **Session Keys**: Rotate every 30 days

**Key Recovery**:
- Master key backup encrypted with recovery key
- Recovery key stored separately (encrypted with user's recovery code)
- SuperAdmin can initiate key recovery (with multi-party approval)
- Audit all key recovery operations

### 6.4 Key Management Service Design

```
KeyManagementService
├── KeyGenerator
│   ├── generateAESKey(key_alias, key_size=256)
│   ├── generateRSAKeyPair(key_alias, key_size=4096)
│   └── generateHMACKey(key_alias)
│
├── KeyAccessor
│   ├── getKey(key_alias) -> Key (never plaintext material)
│   ├── unlockKeystore() -> Requires biometric
│   └── isKeystoreAvailable() -> Boolean
│
├── KeyRotator
│   ├── rotateKey(old_alias, new_alias)
│   ├── reencryptData(old_key, new_key, data)
│   └── updateKeyReferences(new_alias)
│
└── KeyBackup
    ├── backupKey(key_alias, recovery_key)
    ├── restoreKey(backup_data, recovery_key)
    └── verifyBackup(backup_data)
```

---

## 7. Security Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Android Application                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │  Authentication  │      │  Authorization   │            │
│  │     Manager      │◄────►│     Manager      │            │
│  │                  │      │   (RBAC Engine)  │            │
│  └────────┬─────────┘      └────────┬─────────┘            │
│           │                         │                        │
│           ▼                         ▼                        │
│  ┌──────────────────────────────────────────┐               │
│  │      Security Wrapper Layer              │               │
│  │  (Python/Java Bridge for Crypto Ops)     │               │
│  └────────┬─────────────────────────────────┘               │
│           │                                                   │
│           ▼                                                   │
│  ┌──────────────────────────────────────────┐               │
│  │      Android Keystore System              │               │
│  │  (Hardware-Backed Key Storage)            │               │
│  └────────┬─────────────────────────────────┘               │
│           │                                                   │
│           ▼                                                   │
│  ┌──────────────────────────────────────────┐               │
│  │      SQLCipher Wrapper                   │               │
│  │  (AES-256 Encrypted SQLite)              │               │
│  └────────┬─────────────────────────────────┘               │
│           │                                                   │
│           ▼                                                   │
│  ┌──────────────────────────────────────────┐               │
│  │      Encrypted Database                  │               │
│  │  (All records with HMAC)                 │               │
│  └──────────────────────────────────────────┘               │
│                                                               │
│  ┌──────────────────────────────────────────┐               │
│  │      HMAC Integrity Service              │               │
│  │  (Validates all read/write operations)  │               │
│  └──────────────────────────────────────────┘               │
│                                                               │
│  ┌──────────────────────────────────────────┐               │
│  │      Audit Logging Service               │               │
│  │  (All AAA events logged & encrypted)     │               │
│  └──────────────────────────────────────────┘               │
│                                                               │
└─────────────────────────────────────────────────────────────┘
           │                           │
           ▼                           ▼
    ┌─────────────┐           ┌─────────────┐
    │   Network   │           │   Offline   │
    │  (TLS 1.3)  │           │    Cache    │
    └─────────────┘           └─────────────┘
```

---

## 8. Implementation Phases

### Phase 1.1: Foundation (Week 1-2)
- [ ] Android Keystore integration
- [ ] Key generation and storage
- [ ] Basic encryption/decryption utilities

### Phase 1.2: Database Layer (Week 3-4)
- [ ] SQLCipher integration
- [ ] Database schema design
- [ ] Encrypted database wrapper implementation
- [ ] Least privilege access control

### Phase 1.3: Integrity Layer (Week 5-6)
- [ ] HMAC service implementation
- [ ] Integrity validation on read/write
- [ ] Batch validation service
- [ ] Tamper detection and alerting

### Phase 1.4: Authentication (Week 7-8)
- [ ] Biometric authentication integration
- [ ] Credential fallback (PIN/Password)
- [ ] Session management
- [ ] Recovery mechanism

### Phase 1.5: Authorization (Week 9-10)
- [ ] RBAC implementation
- [ ] Permission checking engine
- [ ] Role management
- [ ] Resource access control

### Phase 1.6: Accounting (Week 11-12)
- [ ] Audit logging service
- [ ] Log encryption and integrity
- [ ] Compliance reporting
- [ ] Log retention and archival

---

## 9. Security Considerations

### 9.1 Threat Model

**Threats Addressed**:
1. **Data Theft**: Mitigated by encryption at rest and in transit
2. **Data Tampering**: Mitigated by HMAC integrity checks
3. **Unauthorized Access**: Mitigated by authentication and authorization
4. **Key Compromise**: Mitigated by Android Keystore and key rotation
5. **Privilege Escalation**: Mitigated by RBAC and least privilege
6. **Audit Log Tampering**: Mitigated by append-only logs with HMAC

### 9.2 Compliance Requirements

- **GDPR**: Data encryption, right to deletion, audit trails
- **SOC 2**: Access controls, encryption, monitoring
- **ISO 27001**: Information security management
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover

### 9.3 Security Testing

- **Penetration Testing**: Regular security audits
- **Code Review**: Security-focused code reviews
- **Dependency Scanning**: Regular vulnerability scans
- **Key Management Audit**: Quarterly key management reviews

---

## 10. References

- Android Keystore System: https://developer.android.com/training/articles/keystore
- SQLCipher: https://www.zetetic.net/sqlcipher/
- NIST SP 800-63B: Digital Identity Guidelines
- OWASP Mobile Security: https://owasp.org/www-project-mobile-security/
- RFC 7519: JSON Web Token (JWT)

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Next Review**: Quarterly

