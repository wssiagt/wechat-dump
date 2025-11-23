@echo off
REM Frida Server Manager for Android (Windows)
REM Manage frida-server lifecycle on rooted Android device

set FRIDA_SERVER_PATH=/data/local/tmp/frida-server

if "%1"=="start" goto start
if "%1"=="stop" goto stop
if "%1"=="status" goto status
if "%1"=="restart" goto restart
goto usage

:start
echo [*] Starting frida-server on Android device...

REM Check if already running
adb shell su -c "ps | grep frida-server | grep -v grep" >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [!] frida-server is already running
    adb shell su -c "ps | grep frida-server | grep -v grep"
    goto end
)

REM Start frida-server
adb shell su -c "%FRIDA_SERVER_PATH% &"
timeout /t 2 /nobreak >nul

REM Verify it started
adb shell su -c "ps | grep frida-server | grep -v grep" >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [+] frida-server started successfully
    adb shell su -c "ps | grep frida-server | grep -v grep"
) else (
    echo [!] Failed to start frida-server
)
goto end

:stop
echo [*] Stopping frida-server on Android device...
adb shell su -c "killall frida-server" >nul 2>&1
timeout /t 1 /nobreak >nul

REM Verify it stopped
adb shell su -c "ps | grep frida-server | grep -v grep" >nul 2>&1
if %ERRORLEVEL%==1 (
    echo [+] frida-server stopped successfully
) else (
    echo [!] frida-server still running, forcing kill...
    adb shell su -c "killall -9 frida-server" >nul 2>&1
)
goto end

:status
echo [*] Checking frida-server status...
adb shell su -c "ps | grep frida-server | grep -v grep" >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [+] frida-server is running:
    adb shell su -c "ps | grep frida-server | grep -v grep"
) else (
    echo [-] frida-server is not running
)
goto end

:restart
call %0 stop
timeout /t 2 /nobreak >nul
call %0 start
goto end

:usage
echo Frida Server Manager (Windows)
echo.
echo Usage: %0 {start^|stop^|restart^|status}
echo.
echo Commands:
echo   start    - Start frida-server on device
echo   stop     - Stop frida-server on device
echo   restart  - Restart frida-server
echo   status   - Check if frida-server is running
echo.
echo Examples:
echo   %0 start
echo   %0 status
echo   %0 stop
goto end

:end
