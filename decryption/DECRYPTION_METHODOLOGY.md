# WeChat EnMicroMsg.db Decryption Methodology (2024-2025)

## Overview

This document describes the current working methodology for decrypting WeChat's Android database files, particularly `EnMicroMsg.db`, which contains chat messages. This methodology was developed and tested in November 2024 and works with current WeChat versions (8.0+).

## Problem Statement

WeChat encrypts its local SQLite databases using **WCDB (WeChat Database)**, a custom implementation based on SQLCipher. Traditional decryption methods that relied on calculating the password from `MD5(IMEI + UIN)[:7]` no longer work consistently with modern WeChat versions due to:

1. Changes in key derivation algorithms
2. Different device ID sources (not always IMEI)
3. WeChat version-specific encryption updates
4. Device-specific variations

## WeChat Database Encryption Architecture

### Database Location
```
/data/user/0/com.tencent.mm/MicroMsg/[32-character-hash]/EnMicroMsg.db
```

### Encryption Details
- **Engine**: WCDB (based on SQLCipher)
- **Algorithm**: AES-256
- **Key Format**: 7-character hexadecimal string (e.g., `874986d`)
- **Implementation**: `com.tencent.wcdb.database.SQLiteDatabase`

### SQLCipher Configuration
```sql
PRAGMA key = '[password]';
PRAGMA cipher_use_hmac = OFF;
PRAGMA cipher_page_size = 1024;
PRAGMA kdf_iter = 4000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;
```

## Methodology Evolution

### Method 1: Static Key Derivation (Legacy - Unreliable)

**Approach**: Calculate password from device identifiers
```python
import hashlib
password = hashlib.md5(f"{IMEI}{UIN}".encode()).hexdigest()[:7]
```

**Status**: ❌ Not reliable for WeChat 8.0+

**Reasons for Failure**:
- WeChat may use Android ID instead of IMEI
- Multiple IMEI values on dual-SIM devices
- Encryption algorithm changes in newer versions
- Requires extracting UIN from WeChat files

### Method 2: Hook Database Open Methods (Partially Working)

**Approach**: Hook `com.tencent.wcdb.database.SQLiteDatabase.openDatabase()`

**Challenge**: Method signature varies by WeChat version. Available overloads:
```javascript
.overload('java.lang.String', 'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory', 'int')
.overload('java.lang.String', 'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory', 'int', 'com.tencent.wcdb.DatabaseErrorHandler')
.overload('java.lang.String', 'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory', 'int', 'com.tencent.wcdb.DatabaseErrorHandler', 'int')
.overload('java.lang.String', '[B', 'com.tencent.wcdb.database.SQLiteCipherSpec', 'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory', 'int', 'com.tencent.wcdb.DatabaseErrorHandler')
.overload('java.lang.String', '[B', 'com.tencent.wcdb.database.SQLiteCipherSpec', 'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory', 'int', 'com.tencent.wcdb.DatabaseErrorHandler', 'int')
```

**Status**: ⚠️ Works but requires version-specific adjustments

**Limitation**: Must hook before database is opened

### Method 3: Java.choose on SQLiteConnection (Current - Recommended ✅)

**Approach**: Enumerate existing database connections and read passwords from memory

**Implementation**:
```javascript
Java.performNow(function() {
    Java.choose("com.tencent.wcdb.database.SQLiteConnection", {
        onMatch: function(instance) {
            if(instance.mConnectionId.value != 0) return
            console.log(instance.toString());
            var buffer = instance.mPassword.value;
            if(buffer == null) buffer = []
            var result = "";
            for(var i = 0; i < buffer.length; ++i){
                result += (String.fromCharCode(buffer[i] & 0xff));
            }
            console.log(`password: ${result}`);
        },
        onComplete: function() {}
    });
});
```

**Advantages**:
- ✅ Works with already-opened databases
- ✅ Version-independent (reads from memory)
- ✅ No need to match exact method signatures
- ✅ Captures all database passwords simultaneously

**Status**: ✅ Currently working method (tested Nov 2024)

## Step-by-Step Decryption Process

### Prerequisites
```bash
# Rooted Android device
# Frida installed on PC
pip install frida frida-tools

# Frida server running on device
VERSION=$(frida --version)
ARCH=arm64  # or arm, x86, x86_64
wget https://github.com/frida/frida/releases/download/$VERSION/frida-server-$VERSION-android-$ARCH.xz
xz -d frida-server-$VERSION-android-$ARCH.xz
adb push frida-server-$VERSION-android-$ARCH /data/local/tmp/
adb shell su -c "chmod 777 /data/local/tmp/frida-server-$VERSION-android-$ARCH"
adb shell su -c "/data/local/tmp/frida-server-$VERSION-android-$ARCH &"

# Port forwarding
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043
```

### Step 1: Extract Database Password

```bash
# Ensure WeChat is running on device
frida-ps -U | grep WeChat

# Run password extraction script
cd wechat-dump/decryption
frida -U -n WeChat -l wechatdbpass.js
# For Chinese system: frida -U -n 微信 -l wechatdbpass.js
```

**Output Example**:
```
SQLiteConnection: /data/user/0/com.tencent.mm/MicroMsg/427babc8b5e4d7b79d719b5843e62a4d/EnMicroMsg.db (0)
password: 874986d
```

### Step 2: Pull Database from Device

```bash
# Copy the path from frida output
adb pull /data/user/0/com.tencent.mm/MicroMsg/[hash]/EnMicroMsg.db ./
```

### Step 3: Decrypt with SQLCipher

```bash
sqlcipher EnMicroMsg.db
```

In SQLCipher shell:
```sql
PRAGMA key = '874986d';  -- Use password from Step 1
PRAGMA cipher_use_hmac = OFF;
PRAGMA cipher_page_size = 1024;
PRAGMA kdf_iter = 4000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;

-- Verify decryption
SELECT count(*) FROM sqlite_master;
.tables
.schema message

-- Export decrypted database (optional)
ATTACH DATABASE 'EnMicroMsg_decrypted.db' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
```

### Step 4: Query Chat Messages

```sql
-- View message table structure
.schema message

-- Query recent messages
SELECT
    createTime,
    talker,
    content,
    type
FROM message
ORDER BY createTime DESC
LIMIT 100;

-- Export to CSV
.mode csv
.output messages.csv
SELECT * FROM message;
.output stdout
```

## Important Database Tables

| Table | Description |
|-------|-------------|
| `message` | Chat messages (primary table) |
| `rconversation` | Conversation list |
| `Contact` | Contact information |
| `chatroom` | Group chat information |
| `voiceinfo` | Voice message metadata |
| `ImgInfo2` | Image message metadata |
| `videoinfo2` | Video message metadata |

## Troubleshooting

### Issue: Frida Connection Failed
```bash
# Check device connection
adb devices

# Verify frida-server is running
adb shell su -c "ps | grep frida"

# Restart frida-server if needed
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server-17.5.1-android-arm64 &"
```

### Issue: WeChat Process Not Found
```bash
# Check exact process name
frida-ps -U | grep -i wechat
frida-ps -U | grep -i 微信

# Use correct process name
frida -U -n "WeChat" -l wechatdbpass.js
```

### Issue: SQLCipher Decryption Failed
```
Error: file is not a database
```

**Possible Causes**:
1. Wrong password
2. Missing PRAGMA settings
3. Corrupted database file
4. Wrong PRAGMA order (key must be first)

**Solution**:
```bash
# Re-extract password with Frida
# Ensure all PRAGMA settings are correct
# Try pulling database again from device
```

### Issue: Empty Password Field
Some databases are unencrypted (empty password). These can be opened with standard SQLite:
```bash
sqlite3 database_name.db
```

## Technical Deep Dive

### WCDB Architecture

WeChat uses WCDB, a modified version of SQLCipher with custom optimizations:

```
┌─────────────────────────────────────┐
│  WeChat Application Layer           │
├─────────────────────────────────────┤
│  com.tencent.wcdb.database          │
│  ├─ SQLiteDatabase                  │
│  ├─ SQLiteConnection                │
│  └─ SQLiteCipherSpec                │
├─────────────────────────────────────┤
│  libwcdb.so (Native Library)        │
├─────────────────────────────────────┤
│  SQLCipher Core                     │
└─────────────────────────────────────┘
```

### Memory Layout of SQLiteConnection

```java
class SQLiteConnection {
    int mConnectionId;              // Connection identifier
    SQLiteConnectionPool mPool;
    byte[] mPassword;               // ← Target: Database password
    SQLiteDatabaseConfiguration mConfiguration; // Contains db path
    // ...
}
```

### Key Extraction from Memory

The Frida script accesses:
1. **`mConnectionId`**: Filter for primary connections (value = 0)
2. **`mPassword`**: Byte array containing the password
3. **`mConfiguration.path`**: Database file path

### Password Format Analysis

Observed password patterns:
```
874986d  → 7 hex characters (common)
001addf  → Leading zeros preserved
714f68e  → Lowercase hex
```

**Pattern**: `[0-9a-f]{7}` (28-bit hexadecimal)

**Entropy**: 16^7 = 268,435,456 combinations

## Alternative Approaches

### Brute Force Attack
Given the 28-bit keyspace, brute forcing is feasible:

```python
# EnMicroMsg.db-Password-Cracker approach
# Estimated time: Hours to days depending on hardware
# Tools: hashcat, custom SQLCipher crackers
```

### Static Analysis of WeChat APK
1. Decompile WeChat APK with jadx/apktool
2. Locate password generation code
3. Reverse engineer algorithm
4. Calculate password

**Status**: Time-consuming, breaks with updates

### Backup Extraction
```bash
# For some Xiaomi devices
# Settings > Backup > Phone Backup
# Extract .bak file from: MIUI/backup/AllBackup/
```

## Security Considerations

### Ethical Usage
This methodology should only be used for:
- Personal data recovery
- Authorized forensic analysis
- Security research
- Educational purposes
- Authorized penetration testing

### Legal Compliance
- ✅ Accessing your own WeChat data
- ✅ Authorized forensic investigations
- ❌ Unauthorized access to others' accounts
- ❌ Violating privacy laws

### Data Protection
After decryption:
1. Store decrypted databases securely
2. Delete temporary files
3. Don't share passwords publicly
4. Respect user privacy

## Future Considerations

### Potential WeChat Updates
1. **Increased key length**: 7 → 16+ characters
2. **Hardware-backed encryption**: TEE/Secure Element
3. **Dynamic keys**: Per-session password rotation
4. **Additional authentication**: Biometric requirement

### Methodology Maintenance
- Monitor WeChat updates (check monthly)
- Test scripts with new versions
- Update method signatures as needed
- Document version-specific changes

### Recommended Monitoring
```bash
# Check WeChat version
adb shell dumpsys package com.tencent.mm | grep versionName

# Test decryption after updates
frida-ps -U | grep WeChat
frida -U -n WeChat -l wechatdbpass.js
```

## References

### Tools
- **Frida**: https://frida.re/
- **SQLCipher**: https://www.zetetic.net/sqlcipher/
- **wechat-dump**: https://github.com/ppwwyyxx/wechat-dump
- **WCDB**: https://github.com/Tencent/wcdb

### Research
- Original wechatdbpass.js: https://github.com/ellermister/wechat-clean
- KanXue Forum: bbs.kanxue.com/thread-278092.htm (WeChat 8.0.38 analysis)
- CSDN blogs on WeChat database decryption

### Related Projects
- AndroidWechatSQLiteDecrypt: Xposed module for key extraction
- EnMicroMsg.db-Password-Cracker: Brute force tool
- wechat-backup: Automated backup and decryption

## Changelog

### 2024-11-23
- Documented working methodology for WeChat 8.0+
- Verified `Java.choose` approach on current WeChat version
- Tested on Android device with Frida 17.5.1
- Successfully extracted EnMicroMsg.db password: `874986d`
- Confirmed SQLCipher PRAGMA configuration

### Future Updates
Document version-specific changes and new decryption methods here.

## Contributing

When updating this methodology:
1. Test with current WeChat version
2. Document version number and date
3. Provide working code examples
4. Update troubleshooting section
5. Add to changelog

---

**Last Updated**: 2024-11-23
**Tested WeChat Version**: 8.0.x
**Tested Android Version**: Android 11+
**Frida Version**: 17.5.1
