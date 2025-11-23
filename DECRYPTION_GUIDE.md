# WeChat Database Decryption Guide

Quick reference guide for decrypting WeChat Android databases.

## Overview

WeChat encrypts its databases using **WCDB** (WeChat Database), based on SQLCipher with AES-256 encryption. The password is a 7-character hex string (e.g., `874986d`).

## Quick Start

### 1. Extract Password (Frida)

```bash
# Ensure device is rooted and frida-server is running
cd decryption
frida -U -n WeChat -l wechatdbpass.js

# Output will show:
# SQLiteConnection: /data/.../EnMicroMsg.db (0)
# password: 874986d
```

### 2. Decrypt Database

```bash
cd ..
python decrypt.py 874986d

# Output: EnMicroMsg_decrypted.db
```

### 3. Read Database

```bash
python read_db.py EnMicroMsg_decrypted.db messages
python read_db.py EnMicroMsg_decrypted.db contacts
```

## Tools

### Password Extraction

**File**: `decryption/wechatdbpass.js`

**Method**: Uses `Java.choose()` to find SQLiteConnection instances in memory

**Why it works**:
- Reads from memory (no method signature needed)
- Works with already-opened databases
- Version-independent

**Requirements**:
- Rooted Android device
- Frida server running
- WeChat running on device

### Decryption

**File**: `decrypt.py`

**Usage**:
```bash
python decrypt.py <password> [input_db] [output_db]
```

**Functions**:
- `pull_database_from_device()` - Pull from Android device
- `test_decryption()` - Verify password works
- `export_decrypted_database()` - Export to unencrypted SQLite

**SQLCipher Parameters** (WCDB):
```python
PRAGMA key = 'password'
PRAGMA cipher_use_hmac = OFF
PRAGMA cipher_page_size = 1024
PRAGMA kdf_iter = 4000
PRAGMA cipher_hmac_algorithm = HMAC_SHA1
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1
```

### Database Reading

**File**: `read_db.py`

**Usage**:
```bash
python read_db.py <db_path> [action]
```

**Actions**:
- `messages` - Read recent messages (default)
- `contacts` - List contacts
- `chatrooms` - List group chats
- `stats` - Database statistics
- `tables` - List all tables
- `export` - Export to CSV
- `sql` - Interactive SQL mode

## Database Structure

### Key Tables

| Table | Description |
|-------|-------------|
| `message` | Chat messages (type: 1=text, 3=image, 34=voice, 43=video) |
| `rcontact` | Contacts list |
| `rconversation` | Conversation list |
| `chatroom` | Group chat info |

### Message Table Schema

```sql
CREATE TABLE message (
    msgId INTEGER PRIMARY KEY,
    msgSvrId INTEGER,
    type INT,           -- 1=text, 3=image, 34=voice, 43=video, 47=emoji, 49=link
    status INT,
    isSend INT,         -- 1=sent, 0=received
    createTime INT,     -- Unix timestamp (milliseconds)
    talker TEXT,        -- Username or chatroom ID
    content TEXT        -- Message content (text messages)
)
```

## Development Workflow

### Standard Workflow

```bash
# 1. Extract password
cd decryption && frida -U -n WeChat -l wechatdbpass.js

# 2. Pull and decrypt
cd .. && python decrypt.py 874986d

# 3. Read data
python read_db.py EnMicroMsg_decrypted.db messages
```

### Python Integration

```python
import sqlite3

# Open decrypted database (standard SQLite)
conn = sqlite3.connect('EnMicroMsg_decrypted.db')
cursor = conn.cursor()

# Query messages
cursor.execute("SELECT * FROM message WHERE type = 1 ORDER BY createTime DESC LIMIT 10")
messages = cursor.fetchall()

conn.close()
```

### Automated Script

```python
from decrypt import export_decrypted_database

# Decrypt database programmatically
export_decrypted_database('EnMicroMsg.db', '874986d', 'output.db')
```

## Troubleshooting

### Password Extraction Fails

**Issue**: `frida -U -n WeChat -l wechatdbpass.js` shows no password

**Solutions**:
1. Make sure WeChat is running and logged in
2. Navigate in WeChat to trigger database access
3. Check process name: `frida-ps -U | grep -i wechat`
4. For Chinese system: `frida -U -n 微信 -l wechatdbpass.js`

### Decryption Fails

**Issue**: "file is not a database" error

**Solutions**:
1. Verify password is correct (re-run Frida extraction)
2. Ensure using encrypted database as input
3. Check all PRAGMA parameters are set correctly

### Database Not Found

**Issue**: Cannot pull database from device

**Solutions**:
```bash
# Find database manually
adb shell su -c "find /data/data/com.tencent.mm/MicroMsg -name EnMicroMsg.db"

# Pull manually
adb pull /data/data/com.tencent.mm/MicroMsg/[hash]/EnMicroMsg.db
```

## Technical Details

### Why Old Methods Don't Work

**IMEI + UIN MD5 Method**:
- Used in older WeChat versions
- Password = MD5(IMEI + UIN)[:7]
- No longer reliable for WeChat 8.0+
- Reasons: Different device IDs, algorithm changes

**Current Method**:
- Extract password directly from memory using Frida
- Works regardless of how password is generated
- Version-independent approach

### Encryption Details

- **Algorithm**: AES-256 (SQLCipher)
- **Key Format**: 7-character hex string
- **Key Space**: 16^7 = 268,435,456 combinations (28-bit)
- **Database**: WCDB (WeChat's SQLCipher fork)

### File Locations on Device

```
/data/data/com.tencent.mm/
├── MicroMsg/
│   └── [32-char-hash]/
│       ├── EnMicroMsg.db           # Main message database
│       ├── WxFileIndex.db          # File index
│       ├── AppBrandComm.db         # Mini programs
│       └── [other databases]
└── shared_prefs/
    └── system_config_prefs.xml     # Contains UIN (for reference)
```

## Security Notes

1. **Keep decrypted database secure** - Contains unencrypted chat data
2. **Delete when done** - `rm EnMicroMsg_decrypted.db`
3. **Add to .gitignore**:
   ```
   EnMicroMsg.db
   EnMicroMsg_decrypted.db
   *_decrypted.db
   ```

## File Structure

```
wechat-dump/
├── decryption/
│   ├── wechatdbpass.js         # Password extraction (Frida)
│   └── frida.md                # Frida setup instructions
│
├── decrypt.py                  # Decryption tool
├── read_db.py                  # Database reader
├── export_decrypted_db.py      # Alternative export tool
│
├── DECRYPTION_GUIDE.md         # This file
└── EXPORT_USAGE.md             # Export tool usage
```

## Command Reference

```bash
# Password extraction
frida -U -n WeChat -l decryption/wechatdbpass.js

# Decryption
python decrypt.py <password>
python decrypt.py <password> <input_db> <output_db>

# Reading
python read_db.py <db_path>
python read_db.py <db_path> messages
python read_db.py <db_path> contacts
python read_db.py <db_path> sql

# Export (alternative)
python export_decrypted_db.py
python export_decrypted_db.py <input_db> <password> <output_db>
```

## References

- **Frida**: https://frida.re/
- **SQLCipher**: https://www.zetetic.net/sqlcipher/
- **WCDB**: https://github.com/Tencent/wcdb
- **Original wechatdbpass.js**: https://github.com/ellermister/wechat-clean

---

**Last Updated**: 2024-11-23
**Tested WeChat Version**: 8.0+
**Tested Frida Version**: 17.5.1
