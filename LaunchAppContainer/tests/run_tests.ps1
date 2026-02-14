# LaunchAppContainer Test Suite
# Comprehensive test coverage for all features

param(
    [string]$TestDir = ".\test_workspace",
    [string]$LacExe = "..\x64\Release\LaunchAppContainer.exe",
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$PassCount = 0
$FailCount = 0
$TestResults = @()

function Write-TestHeader {
    param([string]$Name)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "TEST: $Name" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
    $script:PassCount++
    $script:TestResults += @{Name=$Message; Status="PASS"}
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    $script:FailCount++
    $script:TestResults += @{Name=$Message; Status="FAIL"}
}

function New-TestConfig {
    param(
        [string]$Path,
        [hashtable]$Settings
    )
    
    $content = "[App]`n"
    foreach ($key in $Settings.Keys) {
        $content += "$key = $($Settings[$key])`n"
    }
    Set-Content -Path $Path -Value $content -Encoding UTF8
}

function Invoke-LaunchAppContainer {
    param(
        [string]$ConfigPath,
        [int]$TimeoutSeconds = 30
    )
    
    $lacDir = Split-Path $LacExe -Parent
    $configDest = Join-Path $lacDir "config.ini"
    
    if (Test-Path $ConfigPath) {
        Copy-Item $ConfigPath $configDest -Force
    }
    
    Push-Location $lacDir
    try {
        $process = Start-Process -FilePath $LacExe -PassThru -Wait -NoNewWindow -ErrorAction SilentlyContinue
        return $process.ExitCode
    } finally {
        Pop-Location
    }
}

function Test-BasicRestrictedToken {
    Write-TestHeader "Basic Restricted Token Mode"
    
    $configPath = Join-Path $TestDir "config_basic.ini"
    New-TestConfig $configPath @{
        moniker = "test-basic"
        exe = "whoami.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Restricted Token mode executed successfully"
    } else {
        Write-Fail "Restricted Token mode failed with exit code: $exitCode"
    }
}

function Test-IntegrityLevels {
    Write-TestHeader "Integrity Level Tests"
    
    $levels = @("low", "medium", "high")
    
    foreach ($level in $levels) {
        $configPath = Join-Path $TestDir "config_il_$level.ini"
        New-TestConfig $configPath @{
            moniker = "test-il-$level"
            exe = "whoami.exe"
            wait = "true"
            newConsole = "true"
            restrictedToken = "true"
            integrityLevel = $level
            log = "true"
        }
        
        $exitCode = Invoke-LaunchAppContainer $configPath
        
        if ($exitCode -eq 0) {
            Write-Pass "Integrity level '$level' executed successfully"
        } else {
            Write-Fail "Integrity level '$level' failed with exit code: $exitCode"
        }
    }
}

function Test-PathAccessLevels {
    Write-TestHeader "Path Access Level Tests"
    
    $accessLevels = @(
        @{Name="ReadOnly"; Syntax="R"},
        @{Name="ReadExecute"; Syntax="RX"},
        @{Name="ReadWrite"; Syntax="RW"},
        @{Name="FullControl"; Syntax="F"}
    )
    
    foreach ($al in $accessLevels) {
        $testPath = Join-Path $TestDir "path_$($al.Name)"
        New-Item -ItemType Directory -Path $testPath -Force | Out-Null
        "test content" | Out-File (Join-Path $testPath "test.txt")
        
        $configPath = Join-Path $TestDir "config_$($al.Name).ini"
        New-TestConfig $configPath @{
            moniker = "test-$($al.Name)"
            exe = "cmd.exe"
            wait = "true"
            newConsole = "true"
            restrictedToken = "true"
            integrityLevel = "low"
            allowPaths = "`"$testPath`:$($al.Syntax)`""
            lowIntegrityOnPaths = "true"
            log = "true"
        }
        
        $exitCode = Invoke-LaunchAppContainer $configPath
        
        if ($exitCode -eq 0) {
            Write-Pass "Path access level '$($al.Name)' executed successfully"
        } else {
            Write-Fail "Path access level '$($al.Name)' failed with exit code: $exitCode"
        }
    }
}

function Test-MultiplePaths {
    Write-TestHeader "Multiple Paths Test"
    
    $path1 = Join-Path $TestDir "multi_path1"
    $path2 = Join-Path $TestDir "multi_path2"
    $path3 = Join-Path $TestDir "multi_path3"
    
    New-Item -ItemType Directory -Path $path1 -Force | Out-Null
    New-Item -ItemType Directory -Path $path2 -Force | Out-Null
    New-Item -ItemType Directory -Path $path3 -Force | Out-Null
    
    $configPath = Join-Path $TestDir "config_multi.ini"
    New-TestConfig $configPath @{
        moniker = "test-multi"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        allowPaths = "`"$path1`:$($al.Syntax)F,$path2`:RW,$path3`:RX`""
        lowIntegrityOnPaths = "true"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Multiple paths configuration executed successfully"
    } else {
        Write-Fail "Multiple paths configuration failed with exit code: $exitCode"
    }
}

function Test-EnvironmentVariables {
    Write-TestHeader "Environment Variable Tests"
    
    $configPath = Join-Path $TestDir "config_env.ini"
    New-TestConfig $configPath @{
        moniker = "test-env"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        env = "TEST_VAR1=Hello,TEST_VAR2=World,TEST_VAR3=12345"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Environment variable override executed successfully"
    } else {
        Write-Fail "Environment variable override failed with exit code: $exitCode"
    }
}

function Test-PathPrepend {
    Write-TestHeader "PATH Prepend Test"
    
    $testPath = Join-Path $TestDir "prepend_path"
    New-Item -ItemType Directory -Path $testPath -Force | Out-Null
    
    $configPath = Join-Path $TestDir "config_prepend.ini"
    New-TestConfig $configPath @{
        moniker = "test-prepend"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        pathPrepend = $testPath
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "PATH prepend executed successfully"
    } else {
        Write-Fail "PATH prepend failed with exit code: $exitCode"
    }
}

function Test-NetworkFilterBasic {
    Write-TestHeader "Network Filter Basic Tests"
    
    $configPath = Join-Path $TestDir "config_net.ini"
    New-TestConfig $configPath @{
        moniker = "test-net"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        networkFilterEnabled = "true"
        networkFilterPort = "8080"
        networkFilterAllowedUrls = "*.example.com,api.test.com"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Network filter basic configuration executed successfully"
    } else {
        Write-Fail "Network filter basic configuration failed with exit code: $exitCode"
    }
}

function Test-NetworkFilterWildcard {
    Write-TestHeader "Network Filter Wildcard Tests"
    
    $wildcardPatterns = @(
        "*",
        "*.github.com",
        "*.example.com,api.test.com,*"
    )
    
    foreach ($pattern in $wildcardPatterns) {
        $configPath = Join-Path $TestDir "config_wildcard_$($pattern.GetHashCode()).ini"
        New-TestConfig $configPath @{
            moniker = "test-wildcard"
            exe = "cmd.exe"
            wait = "true"
            newConsole = "true"
            restrictedToken = "true"
            networkFilterEnabled = "true"
            networkFilterPort = "8080"
            networkFilterAllowedUrls = $pattern
            log = "true"
        }
        
        $exitCode = Invoke-LaunchAppContainer $configPath
        
        if ($exitCode -eq 0) {
            Write-Pass "Network filter wildcard pattern '$pattern' executed successfully"
        } else {
            Write-Fail "Network filter wildcard pattern '$pattern' failed with exit code: $exitCode"
        }
    }
}

function Test-InvalidExePath {
    Write-TestHeader "Invalid Executable Path Test"
    
    $configPath = Join-Path $TestDir "config_invalid.ini"
    New-TestConfig $configPath @{
        moniker = "test-invalid"
        exe = "nonexistent_exe_12345.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -ne 0) {
        Write-Pass "Invalid executable path handled correctly (expected failure)"
    } else {
        Write-Fail "Invalid executable path should have failed"
    }
}

function Test-EmptyAllowPaths {
    Write-TestHeader "Empty AllowPaths Test"
    
    $configPath = Join-Path $TestDir "config_empty.ini"
    New-TestConfig $configPath @{
        moniker = "test-empty"
        exe = "whoami.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Empty allowPaths executed successfully"
    } else {
        Write-Fail "Empty allowPaths failed with exit code: $exitCode"
    }
}

function Test-LowIntegrityOnPaths {
    Write-TestHeader "Low Integrity Label on Paths Test"
    
    $testPath = Join-Path $TestDir "low_il_path"
    New-Item -ItemType Directory -Path $testPath -Force | Out-Null
    
    $configPath = Join-Path $TestDir "config_lowil.ini"
    New-TestConfig $configPath @{
        moniker = "test-lowil"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        allowPaths = "`"$testPath`:F`""
        lowIntegrityOnPaths = "true"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Low integrity label on paths executed successfully"
    } else {
        Write-Fail "Low integrity label on paths failed with exit code: $exitCode"
    }
}

function Test-SkipLowIntegrity {
    Write-TestHeader "Skip Low Integrity Label Test"
    
    $testPath = Join-Path $TestDir "skip_il_path"
    New-Item -ItemType Directory -Path $testPath -Force | Out-Null
    
    $configPath = Join-Path $TestDir "config_skipil.ini"
    New-TestConfig $configPath @{
        moniker = "test-skipil"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        allowPaths = "`"$testPath`:F`""
        lowIntegrityOnPaths = "false"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Skip low integrity label executed successfully"
    } else {
        Write-Fail "Skip low integrity label failed with exit code: $exitCode"
    }
}

function Test-ConPtyMode {
    Write-TestHeader "ConPTY Mode Test"
    
    $configPath = Join-Path $TestDir "config_conpty.ini"
    New-TestConfig $configPath @{
        moniker = "test-conpty"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        conpty = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "ConPTY mode executed successfully"
    } else {
        Write-Fail "ConPTY mode failed with exit code: $exitCode"
    }
}

function Test-CommandLineArgs {
    Write-TestHeader "Command Line Arguments Test"
    
    $lacDir = Split-Path $LacExe -Parent
    Push-Location $lacDir
    
    $exitCode = & $LacExe -m "test-cmdline" -i "whoami.exe" -w -R 2>&1
    $exitCode = $LASTEXITCODE
    
    Pop-Location
    
    if ($exitCode -eq 0) {
        Write-Pass "Command line arguments executed successfully"
    } else {
        Write-Fail "Command line arguments failed with exit code: $exitCode"
    }
}

function Test-SpecialCharactersInPath {
    Write-TestHeader "Special Characters in Path Test"
    
    $testPath = Join-Path $TestDir "path with spaces"
    New-Item -ItemType Directory -Path $testPath -Force | Out-Null
    
    $configPath = Join-Path $TestDir "config_special.ini"
    New-TestConfig $configPath @{
        moniker = "test-special"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        allowPaths = "`"$testPath`:F`""
        lowIntegrityOnPaths = "true"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Special characters in path executed successfully"
    } else {
        Write-Fail "Special characters in path failed with exit code: $exitCode"
    }
}

function Test-LongPath {
    Write-TestHeader "Long Path Test"
    
    $longPath = $TestDir
    for ($i = 0; $i -lt 5; $i++) {
        $longPath = Join-Path $longPath "very_long_directory_name_$i"
    }
    New-Item -ItemType Directory -Path $longPath -Force | Out-Null
    
    $configPath = Join-Path $TestDir "config_longpath.ini"
    New-TestConfig $configPath @{
        moniker = "test-longpath"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        allowPaths = "`"$longPath`:F`""
        lowIntegrityOnPaths = "true"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Long path executed successfully"
    } else {
        Write-Fail "Long path failed with exit code: $exitCode"
    }
}

function Test-CleanupSubdirs {
    Write-TestHeader "Cleanup Subdirs Test"
    
    $testPath = Join-Path $TestDir "cleanup_test"
    New-Item -ItemType Directory -Path $testPath -Force | Out-Null
    $subDir = Join-Path $testPath "subdir_to_clean"
    New-Item -ItemType Directory -Path $subDir -Force | Out-Null
    "test" | Out-File (Join-Path $subDir "test.txt")
    
    $configPath = Join-Path $TestDir "config_cleanup.ini"
    New-TestConfig $configPath @{
        moniker = "test-cleanup"
        exe = "cmd.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "true"
        integrityLevel = "low"
        allowPaths = "`"$testPath`:F`""
        cleanupSubdirs = "true"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "Cleanup subdirs executed successfully"
    } else {
        Write-Fail "Cleanup subdirs failed with exit code: $exitCode"
    }
}

function Test-AppContainerMode {
    Write-TestHeader "AppContainer Mode Test"
    
    $configPath = Join-Path $TestDir "config_ac.ini"
    New-TestConfig $configPath @{
        moniker = "1.0.0.0_x86_en-us_TestProgram_wvx3sa3v3dj1m"
        exe = "whoami.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "false"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "AppContainer mode executed successfully"
    } else {
        Write-Fail "AppContainer mode failed with exit code: $exitCode"
    }
}

function Test-LPACMode {
    Write-TestHeader "LPAC Mode Test"
    
    $configPath = Join-Path $TestDir "config_lpac.ini"
    New-TestConfig $configPath @{
        moniker = "1.0.0.0_x86_en-us_TestProgram_wvx3sa3v3dj1m"
        exe = "whoami.exe"
        wait = "true"
        newConsole = "true"
        restrictedToken = "false"
        lpac = "true"
        log = "true"
    }
    
    $exitCode = Invoke-LaunchAppContainer $configPath
    
    if ($exitCode -eq 0) {
        Write-Pass "LPAC mode executed successfully"
    } else {
        Write-Fail "LPAC mode failed with exit code: $exitCode"
    }
}

# Main execution
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "LaunchAppContainer Test Suite" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Test Directory: $TestDir"
Write-Host "Executable: $LacExe"

if (-not (Test-Path $LacExe)) {
    Write-Host "ERROR: LaunchAppContainer.exe not found at $LacExe" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Path $TestDir -Force | Out-Null

# Run all tests
Test-BasicRestrictedToken
Test-IntegrityLevels
Test-PathAccessLevels
Test-MultiplePaths
Test-EnvironmentVariables
Test-PathPrepend
Test-NetworkFilterBasic
Test-NetworkFilterWildcard
Test-InvalidExePath
Test-EmptyAllowPaths
Test-LowIntegrityOnPaths
Test-SkipLowIntegrity
Test-ConPtyMode
Test-CommandLineArgs
Test-SpecialCharactersInPath
Test-LongPath
Test-CleanupSubdirs
Test-AppContainerMode
Test-LPACMode

# Print summary
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "TEST SUMMARY" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Total Tests: $($PassCount + $FailCount)"
Write-Host "Passed: $PassCount" -ForegroundColor Green
Write-Host "Failed: $FailCount" -ForegroundColor Red

if ($FailCount -eq 0) {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
} else {
    Write-Host "`nSome tests failed. Please review the output above." -ForegroundColor Red
}

# Cleanup
Remove-Item -Path $TestDir -Recurse -Force -ErrorAction SilentlyContinue

exit $FailCount
