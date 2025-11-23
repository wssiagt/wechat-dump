#!/usr/bin/env python3
"""
WeChat Password Extractor
Automatically extract WeChat database password using Frida and save it
"""

import os
import sys
import time
import subprocess
import frida
from pathlib import Path


def check_device():
    """Check if device is connected"""
    try:
        devices = frida.enumerate_devices()
        for device in devices:
            if device.type == 'usb':
                print(f"[+] Found USB device: {device.name} ({device.id})")
                return device
        print("[!] No USB device found")
        return None
    except Exception as e:
        print(f"[!] Error checking device: {e}")
        return None


def check_wechat_running(device):
    """Check if WeChat is running"""
    try:
        processes = device.enumerate_processes()
        for proc in processes:
            if proc.name in ['WeChat', '微信', 'com.tencent.mm']:
                print(f"[+] WeChat is running: {proc.name} (PID: {proc.pid})")
                return proc.name
        print("[!] WeChat is not running")
        return None
    except Exception as e:
        print(f"[!] Error checking WeChat: {e}")
        return None


def extract_password(device, process_name):
    """Extract password using Frida"""

    print(f"[*] Attaching to {process_name}...")

    # Frida script to extract password
    script_code = """
    Java.performNow(function() {
        Java.choose("com.tencent.wcdb.database.SQLiteConnection", {
            onMatch: function(instance) {
                if(instance.mConnectionId.value != 0) return;

                var buffer = instance.mPassword.value;
                if(buffer == null) buffer = [];

                var result = "";
                for(var i = 0; i < buffer.length; ++i){
                    result += (String.fromCharCode(buffer[i] & 0xff));
                }

                if(result) {
                    var path = instance.mConfiguration.value.path.value;
                    send({type: 'password', password: result, path: path});
                }
            },
            onComplete: function() {}
        });
    });
    """

    passwords = {}

    def on_message(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            if payload['type'] == 'password':
                password = payload['password']
                path = payload['path']

                # Check if it's EnMicroMsg.db
                if 'EnMicroMsg.db' in path:
                    passwords['EnMicroMsg.db'] = password
                    print(f"[+] Found EnMicroMsg.db password: {password}")

    try:
        session = device.attach(process_name)
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        print("[*] Script loaded, waiting for database access...")
        print("[*] Please navigate in WeChat to trigger database access...")

        # Wait for password extraction (max 30 seconds)
        for i in range(30):
            time.sleep(1)
            if passwords:
                break
            if i % 5 == 0 and i > 0:
                print(f"[*] Still waiting... ({i}s)")

        script.unload()
        session.detach()

        return passwords.get('EnMicroMsg.db')

    except Exception as e:
        print(f"[!] Error during extraction: {e}")
        return None


def save_password(password, filepath="password.txt"):
    """Save password to file"""
    try:
        with open(filepath, 'w') as f:
            f.write(password)
        print(f"[+] Password saved to: {filepath}")
        return True
    except Exception as e:
        print(f"[!] Error saving password: {e}")
        return False


def load_password(filepath="password.txt"):
    """Load password from file"""
    try:
        if Path(filepath).exists():
            with open(filepath, 'r') as f:
                password = f.read().strip()
            return password
        return None
    except Exception as e:
        print(f"[!] Error loading password: {e}")
        return None


def main():
    """Main function"""

    print("=" * 80)
    print("WeChat Password Extractor")
    print("=" * 80)

    # Change to decryption directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    password_file = "password.txt"

    # Check for existing password
    existing_password = load_password(password_file)
    if existing_password:
        print(f"\n[*] Found existing password: {existing_password}")
        response = input("Extract new password? (y/n): ").strip().lower()
        if response != 'y':
            print("[*] Using existing password")
            return

    # Check device
    print("\n[1] Checking device connection...")
    device = check_device()
    if not device:
        print("[!] Please ensure:")
        print("  1. Device is connected via USB")
        print("  2. USB debugging is enabled")
        print("  3. frida-server is running on device")
        print("\nRun: ./frida_manager.sh start")
        return

    # Check WeChat
    print("\n[2] Checking WeChat process...")
    process_name = check_wechat_running(device)
    if not process_name:
        print("[!] Please start WeChat on your device")
        return

    # Extract password
    print("\n[3] Extracting password...")
    password = extract_password(device, process_name)

    if password:
        print("\n" + "=" * 80)
        print("SUCCESS!")
        print("=" * 80)
        print(f"\nExtracted Password: {password}")

        # Save to file
        save_password(password, password_file)

        print(f"\n[*] You can now use this password to decrypt database:")
        print(f"    cd ..")
        print(f"    python decrypt.py {password}")

    else:
        print("\n[!] Failed to extract password")
        print("[!] Troubleshooting:")
        print("  1. Make sure you navigated in WeChat (open chats, etc.)")
        print("  2. Try running the script again")
        print("  3. Check frida-server is running: ./frida_manager.sh status")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
