# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Windows AppContainer sandbox launcher ("box_opencode") that runs `opencode.exe` (a pre-built AI coding assistant binary) inside an isolated AppContainer/LPAC sandbox. The launcher is a single-file C++ application.

## Build

Requires Visual Studio 2022 with C++ desktop workload and Windows 10 SDK.

```powershell
# Build with MSBuild (adjust path to your VS installation)
& "D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" `
  LaunchAppContainer\LaunchAppContainer.sln /p:Configuration=Release

# Or use the automation script (builds, copies exe to root, cleans opencode data, launches)
.\start.ps1
```

Output: `LaunchAppContainer\x64\Release\LaunchAppContainer.exe`

Build configurations: `Debug|Win32`, `Release|Win32`, `Debug|x64`, `Release|x64` (x64 Release recommended).

Note: `start.ps1` has hardcoded paths (`D:\study_ap\box`). Adjust before use in a different environment.

## Run

```powershell
.\LaunchAppContainer.exe                    # Uses config.ini in same directory
LaunchAppContainer.exe -m <moniker> -i <exe> [-c capabilities] [-w] [-r] [-l] [-k]
```

No test suite. Verify by running the sandbox and checking log output (enable `log = true` in config.ini).

## Architecture

All sandbox logic lives in one file: `LaunchAppContainer/LaunchAppContainer/LaunchAppContainer.cpp` (~3400 lines).

Execution flow in `wmain()`:
1. Parse `config.ini` (or CLI args) → populate global state
2. Create AppContainer profile with capability SIDs
3. Modify ACLs on `allowPaths` to grant sandbox access (saved for restore on exit)
4. Optionally start network filter proxy (`NetworkFilterPlugin`) and inject `HTTP_PROXY`/`HTTPS_PROXY` env vars
5. Optionally prepare Bun virtual drive (`B:\~BUN`) for Bun runtime compatibility
6. Build child environment block (HOME, TEMP, XDG_*, OPENCODE_CONFIG, etc.)
7. Launch target exe inside sandbox via `CreateProcess` with `SECURITY_CAPABILITIES`, optionally through ConPTY
8. On exit: restore ACLs, cleanup Bun drive, shutdown network filter, delete AppContainer profile

Key subsystems within the single .cpp file:
- **Config parsing** (~L1099-1180): INI file reader + CLI argument parser
- **AppContainer management** (~L1323-1370): Profile create/delete via `CreateAppContainerProfile`
- **ACL modification** (~L1371-1580): `GrantFullControlToSidOnPath`, `SetLowIntegrityLabel`, save/restore original security
- **ConPTY** (~L1583-1715): Dynamically loaded from kernel32.dll, input/output relay threads
- **Bun virtual drive** (~L2399-2700): Extracts embedded DLL from Bun exe, maps `B:\~BUN` via `DefineDosDevice`
- **Network filter proxy** (`NetworkFilterPlugin.h` + implementation): HTTP/HTTPS domain-based filtering proxy
- **Process launch** (~L2783-3090): `CreateProcess` with `SECURITY_CAPABILITIES`, ConPTY, job object sandbox

## config.ini Format

```ini
[App]
moniker = your-sandbox              # AppContainer package identifier
displayName = NodeTuiSandbox        # Profile display name
exe = opencode.exe                  # Target executable
wait = true                         # Wait for child process exit
newConsole = false                  # Allocate new console for child
conpty = false                      # Use ConPTY pseudo-console
jobSandbox = true                   # Use job object for additional sandboxing
lowIntegrityOnPaths = false         # Set low integrity label on allowed paths
allowPaths = C:\path\to\dir         # Filesystem paths accessible to sandbox
capabilities = internetClient       # Capability SIDs (semicolon-separated)
log = true                          # Enable logging to timestamped .log file
networkFilterEnabled = true|false   # Enable domain-based network filtering proxy
networkFilterPort = 8080            # Local proxy port
networkFilterAllowedUrls = *.example.com;api.other.com  # Allowed domain patterns
```

## C++ Codebase Conventions

- Targets Windows 10+ (`_WIN32_WINNT 0x0A00`), C++17, Unicode charset, static CRT linking (`/MT`).
- Links: `Userenv.lib`, `Advapi32.lib`, `OneCoreUAP.lib`.
- RAII wrappers: `SidAttrWrap` (SID ownership), `SavedSecurity` (ACL backup/restore).
- Global state via `static` variables at file scope — no classes for the main logic.
- Naming: PascalCase for structs/functions, camelCase for local variables, `g_` prefix for globals.
- All Windows API calls must have return value checks; use `GetLastError()` for diagnostics.
