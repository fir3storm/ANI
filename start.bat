@echo off
title AI Siege - Autonomous AI Pentest Tool
color 0B

:MENU
cls
echo ============================================================
echo              AI Siege - AI Pentest Tool
echo ============================================================
echo.
echo 1. Run Basic Scan (Manual Login)
echo 2. Run Scan with Credentials
echo 3. Run Scan with Exported Session File (Firefox Add-on)
echo 4. Run Scan with Saved Session (Internal)
echo 5. Manage Sessions
echo 6. Manage Auth Profiles
echo 7. List Available Tests
echo 8. Show Tool Version
echo 9. Exit
echo.
echo ============================================================

set /p choice="Enter your choice (1-9): "

if "%choice%"=="1" goto SCAN_MANUAL
if "%choice%"=="2" goto SCAN_CREDS
if "%choice%"=="3" goto SCAN_SESSION_FILE
if "%choice%"=="4" goto SCAN_SESSION
if "%choice%"=="5" goto MANAGE_SESSIONS
if "%choice%"=="6" goto MANAGE_AUTH
if "%choice%"=="7" goto LIST_TESTS
if "%choice%"=="8" goto VERSION
if "%choice%"=="9" goto EXIT

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto MENU

:SCAN_MANUAL
cls
echo ============================================================
echo                 Run Basic Scan (Manual Login)
echo ============================================================
echo.
set /p url="Enter Target URL: "
if "%url%"=="" goto MENU
echo.
echo Starting scan. Browser will open for manual login...
echo Press ENTER in the terminal after you have logged in.
python -m src.cli scan "%url%"
echo.
pause
goto MENU

:SCAN_CREDS
cls
echo ============================================================
echo                 Run Scan with Credentials
echo ============================================================
echo.
set /p url="Enter Target URL: "
set /p profile="Enter Auth Profile Path (e.g., auth_profiles\example.json): "
if "%url%"=="" goto MENU
if "%profile%"=="" goto MENU
echo.
echo Starting scan with credentials...
python -m src.cli scan "%url%" --auth credentials --auth-profile "%profile%"
echo.
pause
goto MENU

:SCAN_SESSION_FILE
cls
echo ============================================================
echo           Run Scan with Exported Session File
echo ============================================================
echo.
set /p url="Enter Target URL: "
set /p sess_file="Enter Path to Exported Session JSON File (no quotes needed): "

:: Strip any quotes the user might have typed
set "sess_file=%sess_file:"=%"

if "%url%"=="" goto MENU
if "%sess_file%"=="" goto MENU
echo.
set /p debug_mode="Enable debug mode to diagnose chat detection? (y/n): "
echo.
echo Starting scan with exported session file...
if /i "%debug_mode%"=="y" (
    python -m src.cli scan "%url%" --auth session --session-file "%sess_file%" --debug-chat
) else (
    python -m src.cli scan "%url%" --auth session --session-file "%sess_file%"
)
echo.
pause
goto MENU

:SCAN_SESSION
cls
echo ============================================================
echo                 Run Scan with Saved Session
echo ============================================================
echo.
set /p url="Enter Target URL: "
set /p session="Enter Session ID: "
if "%url%"=="" goto MENU
if "%session%"=="" goto MENU
echo.
echo Starting scan with saved session...
python -m src.cli scan "%url%" --auth session --session-id "%session%"
echo.
pause
goto MENU

:MANAGE_SESSIONS
cls
echo ============================================================
echo                      Manage Sessions
echo ============================================================
echo.
echo 1. List Sessions
echo 2. Delete Session
echo 3. Back to Main Menu
echo.
set /p subchoice="Enter choice (1-3): "

if "%subchoice%"=="1" (
    python -m src.cli sessions list
    echo.
    pause
    goto MANAGE_SESSIONS
)
if "%subchoice%"=="2" (
    set /p sess_name="Enter Session Name to delete: "
    python -m src.cli sessions delete --name "%sess_name%"
    echo.
    pause
    goto MANAGE_SESSIONS
)
if "%subchoice%"=="3" goto MENU
goto MANAGE_SESSIONS

:MANAGE_AUTH
cls
echo ============================================================
echo                    Manage Auth Profiles
echo ============================================================
echo.
echo 1. Create New Profile (Interactive Wizard)
echo 2. Validate Existing Profile
echo 3. Back to Main Menu
echo.
set /p subchoice="Enter choice (1-3): "

if "%subchoice%"=="1" (
    python -m src.cli auth create-profile
    echo.
    pause
    goto MANAGE_AUTH
)
if "%subchoice%"=="2" (
    set /p prof_path="Enter Profile Path to validate: "
    python -m src.cli auth validate-profile --profile "%prof_path%"
    echo.
    pause
    goto MANAGE_AUTH
)
if "%subchoice%"=="3" goto MENU
goto MANAGE_AUTH

:LIST_TESTS
cls
echo ============================================================
echo                     Available Tests
echo ============================================================
echo.
python -m src.cli list-tests
echo.
pause
goto MENU

:VERSION
cls
echo ============================================================
echo                       Tool Version
echo ============================================================
echo.
python -m src.cli version
echo.
pause
goto MENU

:EXIT
cls
echo ============================================================
echo    Thank you for using AI Prompt Injection Pentest Tool!
echo ============================================================
echo.
timeout /t 2 >nul
exit
