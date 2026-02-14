# PowerShell script - Implement five functions
Write-Host "========== Start executing PowerShell script ==========" -ForegroundColor Green
# 2. Execute MSBuild compilation
Write-Host "[2/5] MSBuild compiling..." -ForegroundColor Yellow
$msbuildPath = "D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
$solutionPath = "D:\study_ap\box\LaunchAppContainer\LaunchAppContainer.sln"

if ((Test-Path $msbuildPath) -and (Test-Path $solutionPath)) {
    & $msbuildPath $solutionPath "/p:Configuration=Release" | Out-Null
    Write-Host "✓ Compilation completed" -ForegroundColor Green
} else {
    Write-Host "✗ Compilation failed: MSBuild or solution file does not exist" -ForegroundColor Red
}

# 3. Copy exe file
Write-Host "[3/5] Copying exe file..." -ForegroundColor Yellow
$exeSource = "D:\study_ap\box\LaunchAppContainer\x64\Release\LaunchAppContainer.exe"
$exeDest = "D:\study_ap\box\LaunchAppContainer.exe"

if (Test-Path $exeSource) {
    Copy-Item -Path $exeSource -Destination $exeDest -Force
    Write-Host "✓ Copy successful" -ForegroundColor Green
} else {
    Write-Host "✗ Copy failed: exe file does not exist" -ForegroundColor Red
}

# 4. Delete folder
Write-Host "[4/5] Deleting folder..." -ForegroundColor Yellow
$folderToDelete = "D:\study_ap\box\opencode"

if (Test-Path $folderToDelete) {
    Remove-Item -Path $folderToDelete -Recurse -Force
    Write-Host "✓ Delete successful" -ForegroundColor Green
} else {
    Write-Host "Info: Folder does not exist" -ForegroundColor Yellow
}

# 5. Execute compiled exe
Write-Host "[5/5] Executing compiled exe..." -ForegroundColor Yellow
$exeToRun = "D:\study_ap\box\LaunchAppContainer.exe"

if (Test-Path $exeToRun) {
    Start-Process -FilePath $exeToRun -Wait
    Write-Host "✓ exe execution completed" -ForegroundColor Green
} else {
    Write-Host "✗ Execution failed: exe file does not exist" -ForegroundColor Red
}

Write-Host "`n========== Script execution completed ==========" -ForegroundColor Green
Read-Host "Press Enter to exit"