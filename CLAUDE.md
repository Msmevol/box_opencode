# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This project ("box_opencode") runs an AI coding assistant (`opencode.exe`) inside a Windows AppContainer sandbox for security isolation. It has two components:

1. **LaunchAppContainer** — A C++ launcher that creates an AppContainer/LPAC sandbox and runs a target executable inside it with restricted permissions.
2. **opencode.exe** — A Node.js-based AI coding assistant (pre-built binary, not built from this repo).

## Build

Requires Visual Studio 2022 with C++ desktop workload and Windows 10 SDK.

Build the launcher with MSBuild:
```powershell
& "D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" `
  "C:\Users\Administrator\Desktop\box\LaunchAppContainer\LaunchAppContainer.sln" `
  /p:Configuration=Release
```

Output: `LaunchAppContainer\LaunchAppContainer\x64\Release\LaunchAppContainer.exe`

The `start.ps1` script automates the full workflow: build → copy exe to root → clean opencode data → launch.

## Run

```powershell
# Automated build + launch
.\start.ps1

# Direct launch (uses config.ini)
.\LaunchAppContainer.exe

# CLI usage
LaunchAppContainer.exe -m <moniker> -i <exe> [-c capabilities] [-w] [-r] [-l] [-k]
```

## Architecture

```
config.ini ──→ LaunchAppContainer.exe (C++)
                  │
                  ├─ Parses config.ini or CLI args
                  ├─ Creates AppContainer sandbox with capability SIDs
                  ├─ Modifies ACLs on allowPaths for sandbox access
                  ├─ Sets up environment variables (HOME, TEMP, XDG_*, OPENCODE_CONFIG)
                  ├─ Applies Bun/OpenCode runtime compatibility
                  └─ Launches opencode.exe inside the sandbox via ConPTY
                        │
                        └─ opencode.exe runs sandboxed
                             ├─ opencode/config/  (configuration)
                             ├─ opencode/cache/   (model definitions, version)
                             ├─ opencode/data/    (sessions, messages, logs)
                             └─ opencode/work/    (working directory)
```

## Key Files

- `LaunchAppContainer/LaunchAppContainer/LaunchAppContainer.cpp` — Single-file C++ implementation (~3300 lines). Contains all sandbox creation logic: AppContainer profile management, SID/capability handling, ACL modification, environment setup, ConPTY pseudo-console, and process launching.
- `config.ini` — Runtime configuration: moniker, exe path, capabilities, allowed filesystem paths.
- `start.ps1` — Build and launch automation script.

## config.ini Format

```ini
[App]
moniker = your-sandbox          # AppContainer package identifier
displayName = NodeTuiSandbox    # Profile display name
exe = opencode.exe              # Target executable
wait = true                     # Wait for child process exit
newConsole = true               # Use ConPTY pseudo-console
lowIntegrityOnPaths = false     # Set low integrity on allowed paths
allowPaths = C:\path\to\dir     # Filesystem paths accessible to sandbox
capabilities = internetClient   # Capability SIDs (semicolon-separated)
```

## C++ Codebase Notes

- Targets Windows 10+ (`_WIN32_WINNT 0x0A00`), compiled with C++17, Unicode charset, static CRT linking.
- Links against `Userenv.lib`, `Advapi32.lib`, `OneCoreUAP.lib`.
- Key structs: `SidAttrWrap` (RAII wrapper for SID_AND_ATTRIBUTES), `EnvKV` (environment variable pairs), `SavedSecurity` (ACL backup/restore).
- ConPTY functions are loaded dynamically from `kernel32.dll`.
- No test suite exists. Verification is done by running the sandbox and checking log output in `opencode/data/opencode/log/`.
