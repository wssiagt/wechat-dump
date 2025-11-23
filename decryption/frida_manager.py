#!/usr/bin/env python3
"""
Frida Server Manager for Android
Cross-platform Python script to manage frida-server
"""

import sys
import subprocess
import time


def run_adb(command):
    """Run adb command and return output"""
    try:
        result = subprocess.run(
            f'adb shell su -c "{command}"',
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout, result.returncode
    except Exception as e:
        return str(e), 1


def start_frida():
    """Start frida-server"""
    print("[*] Starting frida-server on Android device...")

    # Check if already running
    output, _ = run_adb("ps | grep frida-server | grep -v grep")
    if output.strip():
        print("[!] frida-server is already running")
        print(output)
        return

    # Start frida-server
    run_adb("/data/local/tmp/frida-server &")
    time.sleep(2)

    # Verify
    output, _ = run_adb("ps | grep frida-server | grep -v grep")
    if output.strip():
        print("[+] frida-server started successfully")
        print(output)
    else:
        print("[!] Failed to start frida-server")


def stop_frida():
    """Stop frida-server"""
    print("[*] Stopping frida-server on Android device...")

    # Stop frida-server
    run_adb("killall frida-server")
    time.sleep(1)

    # Verify
    output, _ = run_adb("ps | grep frida-server | grep -v grep")
    if not output.strip():
        print("[+] frida-server stopped successfully")
    else:
        print("[!] frida-server still running, forcing kill...")
        run_adb("killall -9 frida-server")
        time.sleep(1)

        # Final check
        output, _ = run_adb("ps | grep frida-server | grep -v grep")
        if not output.strip():
            print("[+] frida-server stopped")
        else:
            print("[!] Could not stop frida-server")


def status_frida():
    """Check frida-server status"""
    print("[*] Checking frida-server status...")
    output, _ = run_adb("ps | grep frida-server | grep -v grep")

    if output.strip():
        print("[+] frida-server is running:")
        print(output)
    else:
        print("[-] frida-server is not running")


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Frida Server Manager")
        print()
        print("Usage: python frida_manager.py {start|stop|restart|status}")
        print()
        print("Commands:")
        print("  start    - Start frida-server on device")
        print("  stop     - Stop frida-server on device")
        print("  restart  - Restart frida-server")
        print("  status   - Check if frida-server is running")
        print()
        print("Examples:")
        print("  python frida_manager.py start")
        print("  python frida_manager.py status")
        print("  python frida_manager.py stop")
        return

    command = sys.argv[1].lower()

    if command == "start":
        start_frida()
    elif command == "stop":
        stop_frida()
    elif command == "status":
        status_frida()
    elif command == "restart":
        stop_frida()
        time.sleep(2)
        start_frida()
    else:
        print(f"[!] Unknown command: {command}")
        print("Use: start, stop, restart, or status")


if __name__ == "__main__":
    main()
