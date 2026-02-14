@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo LaunchAppContainer Test Suite
echo ============================================================
echo.

set "TEST_DIR=%~dp0test_workspace"
set "LAC_EXE=%~dp0x64\Release\LaunchAppContainer.exe"
set "PASS_COUNT=0"
set "FAIL_COUNT=0"

if not exist "%LAC_EXE%" (
    echo ERROR: LaunchAppContainer.exe not found at %LAC_EXE%
    exit /b 1
)

if not exist "%TEST_DIR%" mkdir "%TEST_DIR%"

echo [INFO] Test workspace: %TEST_DIR%
echo [INFO] Executable: %LAC_EXE%
echo.

call :test_basic_restricted_token
call :test_path_access_readonly
call :test_path_access_readwrite
call :test_path_access_fullcontrol
call :test_low_integrity_label
call :test_env_override
call :test_config_ini
call :test_invalid_path
call :test_wildcard_domain

echo.
echo ============================================================
echo Test Results: PASS=%PASS_COUNT%, FAIL=%FAIL_COUNT%
echo ============================================================

if exist "%TEST_DIR%" rmdir /s /q "%TEST_DIR%" 2>nul

exit /b %FAIL_COUNT%

:test_basic_restricted_token
echo [TEST] Basic Restricted Token Mode
set "CONFIG_FILE=%TEST_DIR%\config_rt.ini"
(
echo [App]
echo moniker = test-rt
echo exe = whoami.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo integrityLevel = low
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Restricted Token mode executed successfully
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Restricted Token mode failed
    set /a FAIL_COUNT+=1
)
exit /b

:test_path_access_readonly
echo [TEST] Path Access - ReadOnly
set "TEST_PATH=%TEST_DIR%\readonly_test"
if not exist "%TEST_PATH%" mkdir "%TEST_PATH%"
echo test > "%TEST_PATH%\test.txt"

set "CONFIG_FILE=%TEST_DIR%\config_ro.ini"
(
echo [App]
echo moniker = test-ro
echo exe = cmd.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo integrityLevel = low
echo allowPaths = "%TEST_PATH%:R"
echo lowIntegrityOnPaths = true
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] ReadOnly path access test passed
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] ReadOnly path access test failed
    set /a FAIL_COUNT+=1
)
exit /b

:test_path_access_readwrite
echo [TEST] Path Access - ReadWrite
set "TEST_PATH=%TEST_DIR%\rw_test"
if not exist "%TEST_PATH%" mkdir "%TEST_PATH%"

set "CONFIG_FILE=%TEST_DIR%\config_rw.ini"
(
echo [App]
echo moniker = test-rw
echo exe = cmd.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo integrityLevel = low
echo allowPaths = "%TEST_PATH%:RW"
echo lowIntegrityOnPaths = true
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] ReadWrite path access test passed
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] ReadWrite path access test failed
    set /a FAIL_COUNT+=1
)
exit /b

:test_path_access_fullcontrol
echo [TEST] Path Access - FullControl
set "TEST_PATH=%TEST_DIR%\fc_test"
if not exist "%TEST_PATH%" mkdir "%TEST_PATH%"

set "CONFIG_FILE=%TEST_DIR%\config_fc.ini"
(
echo [App]
echo moniker = test-fc
echo exe = cmd.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo integrityLevel = low
echo allowPaths = "%TEST_PATH%:F"
echo lowIntegrityOnPaths = true
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] FullControl path access test passed
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] FullControl path access test failed
    set /a FAIL_COUNT+=1
)
exit /b

:test_low_integrity_label
echo [TEST] Low Integrity Label
set "TEST_PATH=%TEST_DIR%\low_il_test"
if not exist "%TEST_PATH%" mkdir "%TEST_PATH%"

set "CONFIG_FILE=%TEST_DIR%\config_lowil.ini"
(
echo [App]
echo moniker = test-lowil
echo exe = cmd.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo integrityLevel = low
echo allowPaths = "%TEST_PATH%:F"
echo lowIntegrityOnPaths = true
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Low integrity label test passed
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Low integrity label test failed
    set /a FAIL_COUNT+=1
)
exit /b

:test_env_override
echo [TEST] Environment Variable Override
set "CONFIG_FILE=%TEST_DIR%\config_env.ini"
(
echo [App]
echo moniker = test-env
echo exe = cmd.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo integrityLevel = low
echo env = TEST_VAR=HelloWorld
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Environment variable override test passed
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Environment variable override test failed
    set /a FAIL_COUNT+=1
)
exit /b

:test_config_ini
echo [TEST] Config.ini File Loading
set "CONFIG_FILE=%TEST_DIR%\config_ini.ini"
(
echo [App]
echo moniker = test-ini
echo displayName = Test INI Loading
echo exe = whoami.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo integrityLevel = low
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Config.ini loading test passed
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Config.ini loading test failed
    set /a FAIL_COUNT+=1
)
exit /b

:test_invalid_path
echo [TEST] Invalid Path Handling
set "CONFIG_FILE=%TEST_DIR%\config_invalid.ini"
(
echo [App]
echo moniker = test-invalid
echo exe = nonexistent_exe_12345.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! neq 0 (
    echo [PASS] Invalid path handling test passed (expected failure)
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Invalid path handling test failed (should have failed)
    set /a FAIL_COUNT+=1
)
exit /b

:test_wildcard_domain
echo [TEST] Wildcard Domain Matching
set "CONFIG_FILE=%TEST_DIR%\config_wildcard.ini"
(
echo [App]
echo moniker = test-wildcard
echo exe = cmd.exe
echo wait = true
echo newConsole = true
echo restrictedToken = true
echo networkFilterEnabled = true
echo networkFilterPort = 8080
echo networkFilterAllowedUrls = "*.example.com,api.test.com,*"
echo log = true
) > "%CONFIG_FILE%"

copy "%CONFIG_FILE%" "%~dp0x64\Release\config.ini" >nul 2>&1
"%LAC_EXE%" >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] Wildcard domain matching test passed
    set /a PASS_COUNT+=1
) else (
    echo [FAIL] Wildcard domain matching test failed
    set /a FAIL_COUNT+=1
)
exit /b
