# Agent Guidelines for LaunchAppContainer

## Project Overview
Windows C++ console application for launching processes in AppContainer/LPAC sandboxes. Built with Visual Studio 2022 (v143 toolset).

## Build Commands

### Full Build
```bash
# Using MSBuild directly
"D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" LaunchAppContainer.sln /p:Configuration=Release

# Or using the PowerShell script
powershell -File start.ps1
```

### Available Configurations
- `Debug|Win32` - 32-bit debug build
- `Release|Win32` - 32-bit release build  
- `Debug|x64` - 64-bit debug build
- `Release|x64` - 64-bit release build (recommended)

### Output Location
- 64-bit: `LaunchAppContainer\x64\Release\LaunchAppContainer.exe`
- 32-bit: `LaunchAppContainer\Release\LaunchAppContainer.exe`

## Code Style Guidelines

### C++ Standards
- Target: Windows 10+ (`_WIN32_WINNT = 0x0A00`)
- Use modern C++ (C++17 features available via ConformanceMode)
- Prefer smart pointers and RAII patterns for resource management
- Use `noexcept` for move operations (see `SidAttrWrap` example)

### Naming Conventions
- Classes/Structs: PascalCase (e.g., `SidAttrWrap`)
- Functions: camelCase or PascalCase (follow existing patterns)
- Variables: camelCase
- Constants/Macros: UPPER_SNAKE_CASE with underscore prefixes
- Member variables: no specific prefix, but be consistent

### Includes
- Platform headers first: `<Windows.h>`, `<UserEnv.h>`, `<sddl.h>`
- Standard library headers after: `<string>`, `<vector>`, `<algorithm>`
- Use `#pragma comment(lib, "...")` for library linking
- Define required Windows version before includes: `#define _WIN32_WINNT 0x0A00`

### Error Handling
- Check Windows API return values
- Use `GetLastError()` for detailed error information
- Free resources properly (use RAII wrappers like `SidAttrWrap`)
- Never leak handles or memory - use move semantics for ownership transfer

### Security
- SDL checks enabled (`SDLCheck` in project settings)
- Static runtime linking for Release builds (`MultiThreaded`)
- This is security-critical code - follow secure coding practices
- All memory allocations must be properly freed
- Validate all external inputs (file paths, moniker strings)

### Memory Management
- Use `LocalFree()` for Windows-allocated SIDs and security descriptors
- Implement move constructors/assignment for resource-owning classes
- Delete copy constructors for non-copyable resource wrappers
- Example pattern: See `SidAttrWrap` implementation

### Compiler Warnings
- Warning Level 3 enabled
- Treat warnings seriously - this is security tooling
- Use `/W4` for stricter checking if adding new code

## Project Structure
```
LaunchAppContainer/
├── LaunchAppContainer.sln          # Visual Studio solution
├── LaunchAppContainer/
│   ├── LaunchAppContainer.cpp      # Main source (single file)
│   ├── LaunchAppContainer.vcxproj  # Project file
│   └── LaunchAppContainer.vcxproj.filters
└── README.md                        # Usage documentation
```

## Testing
- No automated test suite exists
- Manual testing: Build and run with test commands from README.md
- Test with provided moniker: `1.0.0.0_x86_en-us_TestProgram_wvx3sa3v3dj1m`
- Verify both regular AppContainer and LPAC modes

## Important Notes
- This is security research tooling for Windows sandbox testing
- MSRC bounty submissions require specific compiler flags (win32k lockdown)
- Always test in isolated environment - this creates actual sandbox processes
- Single source file architecture - all code in `LaunchAppContainer.cpp`

## Predefined Capabilities for Testing
For LPAC sandbox with basic functionality:
```
S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681
```
