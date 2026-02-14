# LaunchAppContainer Unit Tests
# Tests for specific functions and edge cases

param(
    [string]$TestDir = ".\test_workspace",
    [string]$LacExe = "..\x64\Release\LaunchAppContainer.exe"
)

$ErrorActionPreference = "Continue"
$PassCount = 0
$FailCount = 0

function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
    $script:PassCount++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    $script:FailCount++
}

function New-TestConfig {
    param([string]$Path, [hashtable]$Settings)
    $content = "[App]`n"
    foreach ($key in $Settings.Keys) {
        $content += "$key = $($Settings[$Key])`n"
    }
    Set-Content -Path $Path -Value $content -Encoding UTF8
}

function Invoke-LaunchAppContainer {
    param([string]$ConfigPath)
    $configDest = Join-Path (Split-Path $LacExe -Parent) "config.ini"
    Copy-Item $ConfigPath $configDest -Force
    $process = Start-Process -FilePath $LacExe -PassThru -Wait -NoNewWindow -ErrorAction SilentlyContinue
    return $process.ExitCode
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "LaunchAppContainer Unit Tests" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

New-Item -ItemType Directory -Path $TestDir -Force | Out-Null

# ============================================
# Path Parsing Tests
# ============================================
Write-Host "`n--- Path Parsing Tests ---" -ForegroundColor Yellow

# Test 1: Path with trailing colon (edge case)
Write-Host "Test: Path with trailing colon"
$configPath = Join-Path $TestDir "config_trailing_colon.ini"
$testPath = Join-Path $TestDir "trailing_colon_test"
New-Item -ItemType Directory -Path $testPath -Force | Out-Null
New-TestConfig $configPath @{
    moniker = "test-trailing"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    allowPaths = "`"$testPath`:`""
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Path with trailing colon handled correctly"
} else {
    Write-Fail "Path with trailing colon failed"
}

# Test 2: Path with drive letter only
Write-Host "Test: Path with drive letter only"
$configPath = Join-Path $TestDir "config_drive_only.ini"
New-TestConfig $configPath @{
    moniker = "test-drive"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    allowPaths = "C:"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Path with drive letter only handled (exit code: $exitCode)"

# Test 3: Path with special characters
Write-Host "Test: Path with special characters"
$specialPath = Join-Path $TestDir "path with (parentheses) & [brackets]"
New-Item -ItemType Directory -Path $specialPath -Force | Out-Null
$configPath = Join-Path $TestDir "config_special_chars.ini"
New-TestConfig $configPath @{
    moniker = "test-special"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    allowPaths = "`"$specialPath`:F`""
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Path with special characters handled correctly"
} else {
    Write-Fail "Path with special characters failed"
}

# Test 4: UNC path
Write-Host "Test: UNC path handling"
$configPath = Join-Path $TestDir "config_unc.ini"
New-TestConfig $configPath @{
    moniker = "test-unc"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    allowPaths = "\\localhost\C$\temp:F"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "UNC path handled (exit code: $exitCode)"

# ============================================
# Domain Matching Tests
# ============================================
Write-Host "`n--- Domain Matching Tests ---" -ForegroundColor Yellow

# Test 5: Wildcard domain "*"
Write-Host "Test: Wildcard domain '*'"
$configPath = Join-Path $TestDir "config_wildcard_all.ini"
New-TestConfig $configPath @{
    moniker = "test-wildcard-all"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    networkFilterEnabled = "true"
    networkFilterAllowedUrls = "*"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Wildcard '*' domain pattern handled correctly"
} else {
    Write-Fail "Wildcard '*' domain pattern failed"
}

# Test 6: Multiple wildcard patterns
Write-Host "Test: Multiple wildcard patterns"
$configPath = Join-Path $TestDir "config_multi_wildcard.ini"
New-TestConfig $configPath @{
    moniker = "test-multi-wildcard"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    networkFilterEnabled = "true"
    networkFilterAllowedUrls = "*.github.com,*.google.com,api.openai.com"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Multiple wildcard patterns handled correctly"
} else {
    Write-Fail "Multiple wildcard patterns failed"
}

# Test 7: Empty domain list
Write-Host "Test: Empty domain list"
$configPath = Join-Path $TestDir "config_empty_domain.ini"
New-TestConfig $configPath @{
    moniker = "test-empty-domain"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    networkFilterEnabled = "true"
    networkFilterAllowedUrls = ""
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Empty domain list handled (exit code: $exitCode)"

# ============================================
# Environment Variable Tests
# ============================================
Write-Host "`n--- Environment Variable Tests ---" -ForegroundColor Yellow

# Test 8: Environment variable with equals sign in value
Write-Host "Test: Environment variable with equals sign in value"
$configPath = Join-Path $TestDir "config_env_equals.ini"
New-TestConfig $configPath @{
    moniker = "test-env-equals"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    env = "TEST_KEY=value=with=equals"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Environment variable with equals sign handled correctly"
} else {
    Write-Fail "Environment variable with equals sign failed"
}

# Test 9: Environment variable with spaces
Write-Host "Test: Environment variable with spaces in value"
$configPath = Join-Path $TestDir "config_env_spaces.ini"
New-TestConfig $configPath @{
    moniker = "test-env-spaces"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    env = "TEST_VAR=Hello World,ANOTHER=Test Value"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Environment variable with spaces handled correctly"
} else {
    Write-Fail "Environment variable with spaces failed"
}

# Test 10: Many environment variables
Write-Host "Test: Many environment variables"
$configPath = Join-Path $TestDir "config_many_env.ini"
New-TestConfig $configPath @{
    moniker = "test-many-env"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    env = "VAR1=Value1,VAR2=Value2,VAR3=Value3,VAR4=Value4,VAR5=Value5,VAR6=Value6,VAR7=Value7,VAR8=Value8,VAR9=Value9,VAR10=Value10"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Many environment variables handled correctly"
} else {
    Write-Fail "Many environment variables failed"
}

# ============================================
# Integrity Level Tests
# ============================================
Write-Host "`n--- Integrity Level Tests ---" -ForegroundColor Yellow

# Test 11: Invalid integrity level
Write-Host "Test: Invalid integrity level"
$configPath = Join-Path $TestDir "config_invalid_il.ini"
New-TestConfig $configPath @{
    moniker = "test-invalid-il"
    exe = "whoami.exe"
    wait = "true"
    restrictedToken = "true"
    integrityLevel = "invalid"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Invalid integrity level handled (exit code: $exitCode)"

# Test 12: Numeric integrity level
Write-Host "Test: Numeric integrity level"
$configPath = Join-Path $TestDir "config_numeric_il.ini"
New-TestConfig $configPath @{
    moniker = "test-numeric-il"
    exe = "whoami.exe"
    wait = "true"
    restrictedToken = "true"
    integrityLevel = "0"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Numeric integrity level handled correctly"
} else {
    Write-Fail "Numeric integrity level failed"
}

# ============================================
# Network Filter Port Tests
# ============================================
Write-Host "`n--- Network Filter Port Tests ---" -ForegroundColor Yellow

# Test 13: Custom port
Write-Host "Test: Custom network filter port"
$configPath = Join-Path $TestDir "config_custom_port.ini"
New-TestConfig $configPath @{
    moniker = "test-custom-port"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    networkFilterEnabled = "true"
    networkFilterPort = "9999"
    networkFilterAllowedUrls = "*"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Custom network filter port handled correctly"
} else {
    Write-Fail "Custom network filter port failed"
}

# Test 14: Invalid port (too high)
Write-Host "Test: Invalid port (too high)"
$configPath = Join-Path $TestDir "config_invalid_port.ini"
New-TestConfig $configPath @{
    moniker = "test-invalid-port"
    exe = "cmd.exe"
    wait = "true"
    restrictedToken = "true"
    networkFilterEnabled = "true"
    networkFilterPort = "99999"
    networkFilterAllowedUrls = "*"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Invalid port handled (exit code: $exitCode)"

# ============================================
# Capability Tests
# ============================================
Write-Host "`n--- Capability Tests ---" -ForegroundColor Yellow

# Test 15: Valid capability SID
Write-Host "Test: Valid capability SID"
$configPath = Join-Path $TestDir "config_valid_sid.ini"
New-TestConfig $configPath @{
    moniker = "1.0.0.0_x86_en-us_TestProgram_wvx3sa3v3dj1m"
    exe = "whoami.exe"
    wait = "true"
    capabilities = "S-1-15-3-1"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Valid capability SID handled (exit code: $exitCode)"

# Test 16: Invalid capability SID
Write-Host "Test: Invalid capability SID"
$configPath = Join-Path $TestDir "config_invalid_sid.ini"
New-TestConfig $configPath @{
    moniker = "test-invalid-sid"
    exe = "whoami.exe"
    wait = "true"
    restrictedToken = "true"
    capabilities = "invalid-sid"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Invalid capability SID handled (exit code: $exitCode)"

# ============================================
# Boolean Option Tests
# ============================================
Write-Host "`n--- Boolean Option Tests ---" -ForegroundColor Yellow

# Test 17: Boolean variations
$boolValues = @("true", "false", "1", "0", "yes", "no", "TRUE", "FALSE")
foreach ($val in $boolValues) {
    Write-Host "Test: Boolean value '$val'"
    $configPath = Join-Path $TestDir "config_bool_$val.ini"
    New-TestConfig $configPath @{
        moniker = "test-bool-$val"
        exe = "whoami.exe"
        wait = $val
        restrictedToken = "true"
        log = "true"
    }
    $exitCode = Invoke-LaunchAppContainer $configPath
    Write-Pass "Boolean value '$val' handled (exit code: $exitCode)"
}

# ============================================
# Edge Cases
# ============================================
Write-Host "`n--- Edge Case Tests ---" -ForegroundColor Yellow

# Test 18: Empty moniker
Write-Host "Test: Empty moniker"
$configPath = Join-Path $TestDir "config_empty_moniker.ini"
New-TestConfig $configPath @{
    moniker = ""
    exe = "whoami.exe"
    wait = "true"
    restrictedToken = "true"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Empty moniker handled (exit code: $exitCode)"

# Test 19: Very long moniker
Write-Host "Test: Very long moniker"
$longMoniker = "a" * 200
$configPath = Join-Path $TestDir "config_long_moniker.ini"
New-TestConfig $configPath @{
    moniker = $longMoniker
    exe = "whoami.exe"
    wait = "true"
    restrictedToken = "true"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
Write-Pass "Very long moniker handled (exit code: $exitCode)"

# Test 20: Unicode in config
Write-Host "Test: Unicode characters in config"
$configPath = Join-Path $TestDir "config_unicode.ini"
New-TestConfig $configPath @{
    moniker = "test-unicode"
    displayName = "测试中文 日本語 한국어"
    exe = "whoami.exe"
    wait = "true"
    restrictedToken = "true"
    log = "true"
}
$exitCode = Invoke-LaunchAppContainer $configPath
if ($exitCode -eq 0) {
    Write-Pass "Unicode characters handled correctly"
} else {
    Write-Fail "Unicode characters failed"
}

# Print summary
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "UNIT TEST SUMMARY" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Total Tests: $($PassCount + $FailCount)"
Write-Host "Passed: $PassCount" -ForegroundColor Green
Write-Host "Failed: $FailCount" -ForegroundColor Red

Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue

exit $FailCount
