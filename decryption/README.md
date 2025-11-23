# WeChat Password Extraction Tools

Tools for extracting and managing WeChat database passwords using Frida.

## Files

- **extract_password.py** - Automated password extraction (saves to file)
- **wechatdbpass.js** - Manual Frida script
- **frida_manager.sh** - Frida server manager (Linux/Mac/Git Bash)
- **frida_manager.bat** - Frida server manager (Windows CMD)
- **password.txt** - Saved password (auto-generated)

## Quick Start

### 1. Extract Password (Recommended Method)

```bash
# Start frida-server
./frida_manager.sh start     # Linux/Mac/Git Bash
# or
frida_manager.bat start      # Windows CMD

# Extract password
python extract_password.py

# Password will be saved to password.txt
```

### 2. Use Saved Password

```bash
cd ..
python decrypt.py $(cat decryption/password.txt)
```

## Detailed Usage

### Frida Server Management

**Start frida-server:**
```bash
./frida_manager.sh start
```

**Check status:**
```bash
./frida_manager.sh status
```

**Stop frida-server:**
```bash
./frida_manager.sh stop
```

**Restart:**
```bash
./frida_manager.sh restart
```

### Password Extraction

#### Method 1: Automated (Saves to File)

```bash
python extract_password.py
```

**Features:**
- Checks if password already exists
- Auto-detects device and WeChat process
- Saves password to `password.txt`
- Can be reused without re-extraction

**Output:**
```
[+] Found EnMicroMsg.db password: 874986d
[+] Password saved to: password.txt
```

#### Method 2: Manual (Interactive)

```bash
frida -U -n WeChat -l wechatdbpass.js
# Manually note the password from output
```

### Password File

The extracted password is saved to `password.txt`:

```bash
# View saved password
cat password.txt

# Use in decrypt script
python ../decrypt.py $(cat password.txt)
```

## When to Extract Password

**Extract once when:**
- First time setting up
- After WeChat reinstall
- After device reset
- After major WeChat update (rare)

**The password usually stays the same**, so you can reuse it from `password.txt`

## Workflow Examples

### First Time Setup

```bash
cd decryption

# 1. Start frida-server
./frida_manager.sh start

# 2. Extract and save password
python extract_password.py

# 3. Stop frida-server (optional but recommended)
./frida_manager.sh stop

# 4. Use saved password
cd ..
python decrypt.py $(cat decryption/password.txt)
```

### Subsequent Use (Password Already Saved)

```bash
# Just decrypt with saved password
python decrypt.py $(cat decryption/password.txt)

# No need to run Frida again!
```

### Re-extract Password (if needed)

```bash
cd decryption

# Start frida
./frida_manager.sh start

# Run extraction (will prompt to overwrite)
python extract_password.py

# Stop frida
./frida_manager.sh stop
```

## Troubleshooting

### "No USB device found"

**Solution:**
1. Check device is connected: `adb devices`
2. Check frida-server is running: `./frida_manager.sh status`
3. Restart frida-server: `./frida_manager.sh restart`

### "WeChat is not running"

**Solution:**
1. Open WeChat on your device
2. Make sure you're logged in
3. Run extraction again

### "Failed to extract password"

**Solution:**
1. Navigate in WeChat (open chats, view moments)
2. Wait for script to detect database access
3. Try manual method: `frida -U -n WeChat -l wechatdbpass.js`

### Script hangs at "Still waiting..."

**Solution:**
1. Navigate more in WeChat to trigger database access
2. Open different chats
3. View contact list
4. Check moments/discover

### frida-server won't start

**Solution:**
```bash
# Check if binary exists
adb shell su -c "ls -l /data/local/tmp/frida-server"

# If not found, push frida-server again
# Download from: https://github.com/frida/frida/releases
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server
adb shell su -c "chmod 777 /data/local/tmp/frida-server"
```

## File Management

### View Password
```bash
cat password.txt
```

### Update Password Manually
```bash
echo "874986d" > password.txt
```

### Delete Password
```bash
rm password.txt
```

## Security Notes

1. **password.txt contains sensitive data**
   - Keep it secure
   - Don't commit to version control

2. **Add to .gitignore:**
   ```
   password.txt
   ```

3. **Stop frida-server when not needed:**
   ```bash
   ./frida_manager.sh stop
   ```
   This ensures WeChat runs normally without hooks

## Integration with Decryption Workflow

```bash
# Complete workflow
cd wechat-dump/decryption

# 1. Extract password (first time only)
./frida_manager.sh start
python extract_password.py
./frida_manager.sh stop

# 2. Decrypt database
cd ..
python decrypt.py $(cat decryption/password.txt)

# 3. Read database
python read_db.py EnMicroMsg_decrypted.db messages
```

## Command Reference

```bash
# Frida management
./frida_manager.sh {start|stop|restart|status}
frida_manager.bat {start|stop|restart|status}

# Password extraction
python extract_password.py

# Manual extraction
frida -U -n WeChat -l wechatdbpass.js

# View saved password
cat password.txt

# Use saved password
python ../decrypt.py $(cat password.txt)
```

---

**Tip**: Once you extract the password, you can reuse it without running Frida again until WeChat is reinstalled or the password changes.
