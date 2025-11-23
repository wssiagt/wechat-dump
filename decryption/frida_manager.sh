#!/bin/bash
# Frida Server Manager for Android
# Manage frida-server lifecycle on rooted Android device

FRIDA_SERVER_PATH="/data/local/tmp/frida-server"

case "$1" in
    start)
        echo "[*] Starting frida-server on Android device..."

        # Check if already running
        RUNNING=$(adb shell su -c "ps | grep frida-server | grep -v grep" 2>/dev/null)
        if [ -n "$RUNNING" ]; then
            echo "[!] frida-server is already running"
            echo "$RUNNING"
            exit 0
        fi

        # Start frida-server
        adb shell su -c "$FRIDA_SERVER_PATH &"
        sleep 2

        # Verify it started
        RUNNING=$(adb shell su -c "ps | grep frida-server | grep -v grep" 2>/dev/null)
        if [ -n "$RUNNING" ]; then
            echo "[+] frida-server started successfully"
            echo "$RUNNING"
        else
            echo "[!] Failed to start frida-server"
            exit 1
        fi
        ;;

    stop)
        echo "[*] Stopping frida-server on Android device..."
        adb shell su -c "killall frida-server" 2>/dev/null
        sleep 1

        # Verify it stopped
        RUNNING=$(adb shell su -c "ps | grep frida-server | grep -v grep" 2>/dev/null)
        if [ -z "$RUNNING" ]; then
            echo "[+] frida-server stopped successfully"
        else
            echo "[!] frida-server still running, forcing kill..."
            adb shell su -c "killall -9 frida-server" 2>/dev/null
        fi
        ;;

    status)
        echo "[*] Checking frida-server status..."
        RUNNING=$(adb shell su -c "ps | grep frida-server | grep -v grep" 2>/dev/null)
        if [ -n "$RUNNING" ]; then
            echo "[+] frida-server is running:"
            echo "$RUNNING"
        else
            echo "[-] frida-server is not running"
        fi
        ;;

    restart)
        $0 stop
        sleep 2
        $0 start
        ;;

    *)
        echo "Frida Server Manager"
        echo ""
        echo "Usage: $0 {start|stop|restart|status}"
        echo ""
        echo "Commands:"
        echo "  start    - Start frida-server on device"
        echo "  stop     - Stop frida-server on device"
        echo "  restart  - Restart frida-server"
        echo "  status   - Check if frida-server is running"
        echo ""
        echo "Examples:"
        echo "  $0 start"
        echo "  $0 status"
        echo "  $0 stop"
        exit 1
        ;;
esac
