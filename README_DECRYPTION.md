# WeChat Database Decryption Tools

Simplified tools for extracting, decrypting, and reading WeChat Android databases.

## Quick Start

```bash
# 1. Extract password from device
cd decryption
frida -U -n WeChat -l wechatdbpass.js
# Note the password (e.g., 874986d)

# 2. Decrypt database
cd ..
python decrypt.py 874986d

# 3. Read database
python read_db.py EnMicroMsg_decrypted.db
```

## Tools Overview

### 1. Password Extraction (`decryption/wechatdbpass.js`)

Frida script to extract database password from running WeChat process.

**Usage**:
```bash
frida -U -n WeChat -l decryption/wechatdbpass.js
```

**Requirements**:
- Rooted Android device
- Frida server running on device
- WeChat app running

**Output**:
```
SQLiteConnection: /data/.../EnMicroMsg.db (0)
password: 874986d
```

### 2. Database Decryption (`decrypt.py`)

Tool to pull, test, and decrypt WeChat database.

**Usage**:
```bash
# Basic usage
python decrypt.py <password>

# With custom paths
python decrypt.py <password> <encrypted_db> <output_db>
```

**Features**:
- Auto-pulls database from device if not found locally
- Tests decryption before export
- Exports to unencrypted SQLite database

**Example**:
```bash
python decrypt.py 874986d
# Output: EnMicroMsg_decrypted.db
```

### 3. Database Reader (`read_db.py`)

Tool to read and analyze decrypted WeChat database.

**Usage**:
```bash
python read_db.py <database_path> [action]
```

**Actions**:
- `messages` - Display recent messages (default)
- `contacts` - List contacts
- `chatrooms` - List group chats
- `stats` - Show database statistics
- `tables` - List all tables
- `export` - Export messages to CSV
- `sql` - Interactive SQL query mode

**Examples**:
```bash
# Read messages
python read_db.py EnMicroMsg_decrypted.db

# List contacts
python read_db.py EnMicroMsg_decrypted.db contacts

# Interactive SQL
python read_db.py EnMicroMsg_decrypted.db sql
```

### 4. Export Tool (`export_decrypted_db.py`)

Alternative standalone export tool (kept for compatibility).

**Usage**:
```bash
python export_decrypted_db.py [encrypted_db] [password] [output_db]
```

## Complete Workflow

### Step 1: Setup Frida

```bash
# Install Frida on PC
pip install frida-tools

# Download and push frida-server to device
# (See decryption/frida.md for details)
adb push frida-server /data/local/tmp/
adb shell su -c "chmod 777 /data/local/tmp/frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
```

### Step 2: Extract Password

```bash
cd decryption
frida -U -n WeChat -l wechatdbpass.js

# Note the password from output
# Example: password: 874986d
```

### Step 3: Decrypt Database

```bash
cd ..
python decrypt.py 874986d

# This will:
# 1. Pull EnMicroMsg.db from device (if not exists)
# 2. Test decryption
# 3. Export to EnMicroMsg_decrypted.db
```

### Step 4: Read Data

```bash
# View messages
python read_db.py EnMicroMsg_decrypted.db messages

# View contacts
python read_db.py EnMicroMsg_decrypted.db contacts

# View statistics
python read_db.py EnMicroMsg_decrypted.db stats

# Interactive queries
python read_db.py EnMicroMsg_decrypted.db sql
```

## Development Usage

### Python Integration

```python
import sqlite3

# Standard SQLite (no encryption needed after decryption)
conn = sqlite3.connect('EnMicroMsg_decrypted.db')
cursor = conn.cursor()

# Query messages
cursor.execute("""
    SELECT createTime, talker, content
    FROM message
    WHERE type = 1
    ORDER BY createTime DESC
    LIMIT 10
""")

for create_time, talker, content in cursor.fetchall():
    print(f"{talker}: {content}")

conn.close()
```

### Programmatic Decryption

```python
from decrypt import export_decrypted_database

# Decrypt database in your script
success = export_decrypted_database(
    encrypted_db='EnMicroMsg.db',
    password='874986d',
    output_db='output.db'
)
```

## Database Schema

### Key Tables

**message** - Chat messages
```sql
msgId INTEGER PRIMARY KEY
type INT              -- 1=text, 3=image, 34=voice, 43=video, 47=emoji, 49=link
isSend INT            -- 1=sent, 0=received
createTime INT        -- Unix timestamp (milliseconds)
talker TEXT           -- Username or chatroom ID
content TEXT          -- Message content
```

**rcontact** - Contacts
```sql
username TEXT         -- WeChat ID
nickname TEXT         -- Display name
conRemark TEXT        -- Custom remark
alias TEXT            -- WeChat alias
```

**chatroom** - Group chats
```sql
chatroomname TEXT     -- Group chat ID
displayname TEXT      -- Group name
memberlist TEXT       -- Semicolon-separated member list
roomowner TEXT        -- Group owner ID
```

## Troubleshooting

### Frida Connection Failed

```bash
# Check device connection
adb devices

# Check frida-server running
adb shell su -c "ps | grep frida"

# Restart if needed
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
```

### Password Not Found

- Ensure WeChat is running and logged in
- Navigate in WeChat to trigger database access
- Check process name: `frida-ps -U | grep WeChat`
- For Chinese ROM: Use `frida -U -n 微信 -l wechatdbpass.js`

### Decryption Failed

- Verify password is correct (re-run Frida)
- Ensure using encrypted database as input
- Check that database was pulled correctly

## File Structure

```
wechat-dump/
├── decryption/
│   ├── wechatdbpass.js          # Password extraction (Frida)
│   └── frida.md                 # Frida setup guide
│
├── decrypt.py                   # Main decryption tool
├── read_db.py                   # Database reader
├── export_decrypted_db.py       # Alternative export tool
│
├── DECRYPTION_GUIDE.md          # Detailed guide
└── README_DECRYPTION.md         # This file
```

## Important Notes

### Security

1. **Decrypted database contains sensitive data**
   - Keep it secure
   - Delete when done: `rm EnMicroMsg_decrypted.db`

2. **Add to .gitignore**:
   ```
   EnMicroMsg.db
   EnMicroMsg_decrypted.db
   *_decrypted.db
   ```

### Compatibility

- **WeChat Version**: Tested on 8.0+
- **Android**: Requires root access
- **Frida**: Version 17.5.1+
- **Python**: 3.7+

### Dependencies

```bash
pip install pysqlcipher3 frida-tools
```

## Command Reference

```bash
# Extract password
frida -U -n WeChat -l decryption/wechatdbpass.js

# Decrypt (basic)
python decrypt.py <password>

# Decrypt (custom)
python decrypt.py <password> <input_db> <output_db>

# Read messages
python read_db.py <db_path>
python read_db.py <db_path> messages

# Read contacts
python read_db.py <db_path> contacts

# Statistics
python read_db.py <db_path> stats

# Interactive SQL
python read_db.py <db_path> sql

# Export to CSV
python read_db.py <db_path> export

# Alternative export
python export_decrypted_db.py
python export_decrypted_db.py <encrypted_db> <password> <output_db>
```

## Further Reading

- **DECRYPTION_GUIDE.md** - Detailed technical documentation
- **decryption/frida.md** - Frida setup instructions

---

**Version**: 1.0
**Last Updated**: 2024-11-23
**Tested**: WeChat 8.0+ on Android 11+

Existing password:
The script also found passwords for other WeChat databases:
  - WxFileIndex.db: 874986d
  - AppBrandComm.db: 874986d
  - MicroMsgPriority.db: 001addf
  - FTS5IndexMicroMsg_encrypt.db: 714f68e
  - And several others
