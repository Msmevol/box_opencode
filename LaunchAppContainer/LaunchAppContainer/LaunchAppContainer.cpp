#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <sdkddkver.h>
#include <Windows.h>
#include <UserEnv.h>
#include <sddl.h>
#include <Aclapi.h>

#include <algorithm>
#include <cstdarg>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>

#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OneCoreUAP.lib")

#include "NetworkFilterPlugin.h"

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

struct SidAttrWrap : public SID_AND_ATTRIBUTES {
    SidAttrWrap(SID_AND_ATTRIBUTES obj) : SID_AND_ATTRIBUTES(obj) {}

    SidAttrWrap(SidAttrWrap&& other) noexcept {
        Sid = nullptr;
        Attributes = 0;
        std::swap(Sid, other.Sid);
        std::swap(Attributes, other.Attributes);
    }

    SidAttrWrap& operator=(SidAttrWrap&& other) noexcept {
        if (this != &other) {
            if (Sid) {
                LocalFree(Sid);
            }
            Sid = nullptr;
            Attributes = 0;
            std::swap(Sid, other.Sid);
            std::swap(Attributes, other.Attributes);
        }
        return *this;
    }

    SidAttrWrap(const SidAttrWrap&) = delete;
    SidAttrWrap& operator=(const SidAttrWrap&) = delete;

    ~SidAttrWrap() {
        if (Sid) {
            LocalFree(Sid);
            Sid = nullptr;
        }
    }
};

struct EnvKV {
    std::wstring name;
    std::wstring value;
};

struct SavedSecurity {
    std::wstring path;
    PSECURITY_DESCRIPTOR sdDacl = nullptr;
    PACL dacl = nullptr;
    bool hasDacl = false;
    bool daclProtected = false;

    PSECURITY_DESCRIPTOR sdSacl = nullptr;
    PACL sacl = nullptr;
    bool hasSacl = false;
};

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef DISABLE_NEWLINE_AUTO_RETURN
#define DISABLE_NEWLINE_AUTO_RETURN 0x0008
#endif

typedef HRESULT (WINAPI *FnCreatePseudoConsole)(COORD, HANDLE, HANDLE, DWORD, void**);
typedef void    (WINAPI *FnClosePseudoConsole)(void*);
typedef HRESULT (WINAPI *FnResizePseudoConsole)(void*, COORD);

static WCHAR* ExeToLaunch = nullptr;
static std::wstring PackageMoniker;
static std::wstring PackageDisplayName;

static std::vector<SidAttrWrap> CapabilityList;
static std::vector<std::wstring> AllowedPaths;
static std::vector<EnvKV> EnvOverrides;
static std::vector<std::wstring> PathPrependEntries;
static std::vector<SavedSecurity> g_SavedSecurity;

static std::vector<wchar_t> g_CmdLineBuf;
static std::vector<wchar_t> g_ChildEnv;

static bool WaitForExit = true;
static bool RetainProfile = false;
static bool LaunchAsLpac = false;
static bool NoWin32k = false;
static bool PathLowIntegrity = true;
static bool g_ProfileWasCreated = false;
static bool CleanupAllowedSubdirs = false;
static bool g_WaitAutoEnabled = false;
static bool UseNewConsole = true;
static bool UseConPty = false;
static bool HideParentConsole = true;
static bool g_LogEnabled = false;

// Network Filter Plugin state
static bool g_NetworkFilterEnabled = false;
static int  g_NetworkFilterPort = 8080;
static std::wstring g_NetworkFilterAllowedUrls;

// Bun Virtual Drive (B:\~BUN) state
static volatile LONG g_BunCleanupDone = 0;
static bool g_BunDriveMapped = false;
static std::wstring g_BunStagingDir;
static std::wstring g_BunDriveTarget;
static std::vector<std::wstring> g_BunFallbackDirs;  // .bun fallback dirs to clean up

static volatile LONG g_RestoreDone = 0;
static volatile LONG g_PathAclModified = 0;

static FnCreatePseudoConsole g_pfnCreatePC = nullptr;
static FnClosePseudoConsole  g_pfnClosePC  = nullptr;
static bool g_ConPtyAvailable = false;

// Log file state
static HANDLE g_LogFile = INVALID_HANDLE_VALUE;
static std::wstring g_LogFilePath;

// Proxy log file state (separate from sandbox log)
static HANDLE g_ProxyLogFile = INVALID_HANDLE_VALUE;
static std::wstring g_ProxyLogFilePath;
static volatile LONG g_ProxyAllowCount = 0;
static volatile LONG g_ProxyBlockCount = 0;

// ========================================================================
// Logging
// ========================================================================

// Open log file next to exe. Called once at startup before any logging.
// Log file name: LaunchAppContainer_YYYYMMDD_HHMMSSmmm.log
static void InitLogFile() {
    if (!g_LogEnabled) return;

    wchar_t exePath[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;

    // Find directory part
    std::wstring dir(exePath, n);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        dir = dir.substr(0, pos + 1);
    } else {
        dir = L".\\";
    }

    // Build timestamped filename
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t fname[128] = {};
    _snwprintf_s(fname, _countof(fname), _TRUNCATE,
                 L"LaunchAppContainer_%04u%02u%02u_%02u%02u%02u%03u.log",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    g_LogFilePath = dir + fname;

    g_LogFile = CreateFileW(g_LogFilePath.c_str(),
                            FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_LogFile == INVALID_HANDLE_VALUE) {
        // Fallback: try writing to current directory
        g_LogFilePath = std::wstring(L".\\") + fname;
        g_LogFile = CreateFileW(g_LogFilePath.c_str(),
                                FILE_APPEND_DATA,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (g_LogFile != INVALID_HANDLE_VALUE) {
        // Write UTF-8 BOM if file is new (empty)
        LARGE_INTEGER fileSize{};
        if (GetFileSizeEx(g_LogFile, &fileSize) && fileSize.QuadPart == 0) {
            const BYTE bom[] = { 0xEF, 0xBB, 0xBF };
            DWORD written = 0;
            WriteFile(g_LogFile, bom, sizeof(bom), &written, nullptr);
        }
    }
}

static void CloseLogFile() {
    if (g_LogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_LogFile);
        g_LogFile = INVALID_HANDLE_VALUE;
    }
}

void LogV(PCWSTR level, PCWSTR fmt, va_list ap) {
    if (!g_LogEnabled) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);

    // Format prefix
    wchar_t prefix[80] = {};
    _snwprintf_s(prefix, _countof(prefix), _TRUNCATE,
                 L"[%04u-%02u-%02u %02u:%02u:%02u.%03u][%ls] ",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level);

    // Format message body
    wchar_t body[4096] = {};
    va_list apCopy;
    va_copy(apCopy, ap);
    _vsnwprintf_s(body, _countof(body), _TRUNCATE, fmt, apCopy);
    va_end(apCopy);

    // Write to console
    wprintf(L"%ls%ls\r\n", prefix, body);

    // Write to log file (UTF-8)
    if (g_LogFile != INVALID_HANDLE_VALUE) {
        // Build complete line: prefix + body + \r\n
        std::wstring line = std::wstring(prefix) + body + L"\r\n";

        // Convert to UTF-8
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(),
                                          nullptr, 0, nullptr, nullptr);
        if (utf8Len > 0) {
            std::vector<char> utf8Buf(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(),
                                utf8Buf.data(), utf8Len, nullptr, nullptr);
            DWORD written = 0;
            WriteFile(g_LogFile, utf8Buf.data(), (DWORD)utf8Len, &written, nullptr);
        }
    }
}

void LogInfo(PCWSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogV(L"INFO", fmt, ap);
    va_end(ap);
}

void LogWarn(PCWSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogV(L"WARN", fmt, ap);
    va_end(ap);
}

void LogError(PCWSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogV(L"ERROR", fmt, ap);
    va_end(ap);
}

void LogDebug(PCWSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogV(L"DEBUG", fmt, ap);
    va_end(ap);
}

// ========================================================================
// Proxy Log (separate file for network filter decisions)
// ========================================================================
// Proxy log file: NetworkFilterProxy_YYYYMMDD_HHMMSSmmm.log
// Format:
//   [timestamp] ALLOW  CONNECT api.anthropic.com:443  (rule: *.anthropic.com)
//   [timestamp] BLOCK  GET     evil.example.com       (no matching rule)
//   [timestamp] INFO   Proxy started on 127.0.0.1:8080
// ========================================================================

static void InitProxyLogFile() {
    if (!g_LogEnabled || !g_NetworkFilterEnabled) return;

    wchar_t exePath[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;

    std::wstring dir(exePath, n);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        dir = dir.substr(0, pos + 1);
    } else {
        dir = L".\\";
    }

    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t fname[128] = {};
    _snwprintf_s(fname, _countof(fname), _TRUNCATE,
                 L"NetworkFilterProxy_%04u%02u%02u_%02u%02u%02u%03u.log",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    g_ProxyLogFilePath = dir + fname;

    g_ProxyLogFile = CreateFileW(g_ProxyLogFilePath.c_str(),
                                 FILE_APPEND_DATA,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_ProxyLogFile == INVALID_HANDLE_VALUE) {
        g_ProxyLogFilePath = std::wstring(L".\\") + fname;
        g_ProxyLogFile = CreateFileW(g_ProxyLogFilePath.c_str(),
                                     FILE_APPEND_DATA,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (g_ProxyLogFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fileSize{};
        if (GetFileSizeEx(g_ProxyLogFile, &fileSize) && fileSize.QuadPart == 0) {
            const BYTE bom[] = { 0xEF, 0xBB, 0xBF };
            DWORD written = 0;
            WriteFile(g_ProxyLogFile, bom, sizeof(bom), &written, nullptr);
        }
    }
}

static void CloseProxyLogFile() {
    // Write summary before closing
    if (g_ProxyLogFile != INVALID_HANDLE_VALUE) {
        LONG allows = InterlockedCompareExchange(&g_ProxyAllowCount, 0, 0);
        LONG blocks = InterlockedCompareExchange(&g_ProxyBlockCount, 0, 0);

        SYSTEMTIME st{};
        GetLocalTime(&st);
        wchar_t summary[512] = {};
        _snwprintf_s(summary, _countof(summary), _TRUNCATE,
                     L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] ========== Session summary: %ld ALLOWED, %ld BLOCKED ==========\r\n",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                     allows, blocks);

        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, summary, -1, nullptr, 0, nullptr, nullptr);
        if (utf8Len > 1) {
            std::vector<char> utf8Buf(utf8Len - 1);
            WideCharToMultiByte(CP_UTF8, 0, summary, -1, utf8Buf.data(), utf8Len - 1, nullptr, nullptr);
            DWORD written = 0;
            WriteFile(g_ProxyLogFile, utf8Buf.data(), (DWORD)utf8Buf.size(), &written, nullptr);
        }

        CloseHandle(g_ProxyLogFile);
        g_ProxyLogFile = INVALID_HANDLE_VALUE;
    }
}

// Write a line to the proxy log file (and optionally console)
void ProxyLogWriteLine(PCWSTR line, bool alsoConsole = false) {
    if (alsoConsole) {
        wprintf(L"%ls\r\n", line);
    }

    if (g_ProxyLogFile != INVALID_HANDLE_VALUE) {
        std::wstring full = std::wstring(line) + L"\r\n";
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, full.c_str(), (int)full.size(),
                                          nullptr, 0, nullptr, nullptr);
        if (utf8Len > 0) {
            std::vector<char> utf8Buf(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, full.c_str(), (int)full.size(),
                                utf8Buf.data(), utf8Len, nullptr, nullptr);
            DWORD written = 0;
            WriteFile(g_ProxyLogFile, utf8Buf.data(), (DWORD)utf8Len, &written, nullptr);
        }
    }
}

void LogProxyAllow(const wchar_t* method, const wchar_t* domain, const wchar_t* matchedPattern) {
    InterlockedIncrement(&g_ProxyAllowCount);

    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t line[1024] = {};
    _snwprintf_s(line, _countof(line), _TRUNCATE,
                 L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] ALLOW  %-7ls %ls  (rule: %ls)",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 method, domain, matchedPattern);
    ProxyLogWriteLine(line);
}

void LogProxyBlock(const wchar_t* method, const wchar_t* domain, const wchar_t* reason) {
    InterlockedIncrement(&g_ProxyBlockCount);

    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t line[1024] = {};
    _snwprintf_s(line, _countof(line), _TRUNCATE,
                 L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] BLOCK  %-7ls %ls  (%ls)",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 method, domain, reason);
    // Blocked requests also print to console for visibility
    ProxyLogWriteLine(line, true);
}

void LogProxyV(PCWSTR level, PCWSTR fmt, va_list ap) {
    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t prefix[80] = {};
    _snwprintf_s(prefix, _countof(prefix), _TRUNCATE,
                 L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] %-6ls ",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level);

    wchar_t body[4096] = {};
    va_list apCopy;
    va_copy(apCopy, ap);
    _vsnwprintf_s(body, _countof(body), _TRUNCATE, fmt, apCopy);
    va_end(apCopy);

    wchar_t line[4200] = {};
    _snwprintf_s(line, _countof(line), _TRUNCATE, L"%ls%ls", prefix, body);
    ProxyLogWriteLine(line);
}

void LogProxyInfo(PCWSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogProxyV(L"INFO", fmt, ap);
    va_end(ap);
}

void LogProxyWarn(PCWSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogProxyV(L"WARN", fmt, ap);
    va_end(ap);
}

void LogProxyError(PCWSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogProxyV(L"ERROR", fmt, ap);
    va_end(ap);
}

// ========================================================================
// String / Path Utilities
// ========================================================================
static bool IsSpace(wchar_t ch) {
    return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
}

static std::wstring TrimCopy(const std::wstring& s) {
    size_t b = 0;
    size_t e = s.size();

    while (b < e && IsSpace(s[b])) ++b;
    while (e > b && IsSpace(s[e - 1])) --e;

    std::wstring t = s.substr(b, e - b);
    if (t.size() >= 2) {
        if ((t.front() == L'"' && t.back() == L'"') || (t.front() == L'\'' && t.back() == L'\'')) {
            t = t.substr(1, t.size() - 2);
        }
    }
    return t;
}

static bool IEquals(const std::wstring& a, const std::wstring& b) {
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

static std::wstring ToLowerCopy(std::wstring s) {
    for (auto& ch : s) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return s;
}

static std::wstring NormalizePathForCompare(const std::wstring& in) {
    std::wstring p = TrimCopy(in);
    std::replace(p.begin(), p.end(), L'/', L'\\');

    while (p.size() > 3 && !p.empty() && p.back() == L'\\') {
        p.pop_back();
    }

    if (p.size() == 2 && p[1] == L':') {
        p.push_back(L'\\');
    }

    return p;
}

static bool PathEqualsInsensitive(const std::wstring& a, const std::wstring& b) {
    std::wstring na = NormalizePathForCompare(a);
    std::wstring nb = NormalizePathForCompare(b);
    return _wcsicmp(na.c_str(), nb.c_str()) == 0;
}

static bool VectorHasPathInsensitive(const std::vector<std::wstring>& list, const std::wstring& path) {
    for (const auto& item : list) {
        if (PathEqualsInsensitive(item, path)) {
            return true;
        }
    }
    return false;
}

static bool AddAllowedPathUnique(const std::wstring& path) {
    std::wstring p = TrimCopy(path);
    if (p.empty()) return false;
    if (VectorHasPathInsensitive(AllowedPaths, p)) return false;
    AllowedPaths.emplace_back(p);
    return true;
}

static bool AddPathPrependUnique(const std::wstring& path) {
    std::wstring p = TrimCopy(path);
    if (p.empty()) return false;
    if (VectorHasPathInsensitive(PathPrependEntries, p)) return false;
    PathPrependEntries.emplace_back(p);
    return true;
}

static std::wstring GetEnvVarCopy(PCWSTR name) {
    DWORD need = GetEnvironmentVariableW(name, nullptr, 0);
    if (need == 0) {
        return L"";
    }

    std::vector<wchar_t> buf(need);
    DWORD got = GetEnvironmentVariableW(name, buf.data(), need);
    if (got == 0 || got >= need) {
        return L"";
    }

    return std::wstring(buf.data(), got);
}

static bool DirectoryExists(const std::wstring& path) {
    if (path.empty()) return false;
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static bool IsDotOrDotDot(const wchar_t* name) {
    return name && (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0);
}

static void ClearReadOnlyAttributeIfSet(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return;
    if (attrs & FILE_ATTRIBUTE_READONLY) {
        SetFileAttributesW(path.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
    }
}

static DWORD DeleteTreeNoFollow(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
        return e;
    }

    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        ClearReadOnlyAttributeIfSet(path);
        if (DeleteFileW(path.c_str())) return ERROR_SUCCESS;
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
        return e;
    }

    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
        ClearReadOnlyAttributeIfSet(path);
        if (RemoveDirectoryW(path.c_str())) return ERROR_SUCCESS;
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
        return e;
    }

    std::wstring search = path;
    if (!search.empty() && search.back() != L'\\') search.push_back(L'\\');
    search.append(L"*");

    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (IsDotOrDotDot(fd.cFileName)) continue;
            std::wstring child = path;
            if (!child.empty() && child.back() != L'\\') child.push_back(L'\\');
            child.append(fd.cFileName);

            DWORD dw = DeleteTreeNoFollow(child);
            if (dw != ERROR_SUCCESS) {
                LogWarn(L"DeleteTree failed on %ls (%lu)", child.c_str(), dw);
            }
        } while (FindNextFileW(hFind, &fd));

        DWORD e = GetLastError();
        FindClose(hFind);
        if (e != ERROR_NO_MORE_FILES) {
            return e;
        }
    } else {
        DWORD e = GetLastError();
        if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
            return e;
        }
    }

    ClearReadOnlyAttributeIfSet(path);
    if (RemoveDirectoryW(path.c_str())) return ERROR_SUCCESS;

    DWORD e = GetLastError();
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
    return e;
}

static void DeleteSubdirectoriesOfRoot(const std::wstring& root) {
    std::wstring r = NormalizePathForCompare(root);
    if (r.empty() || r.size() <= 3) {
        LogWarn(L"[Cleanup] Refuse to clean subdirs of drive root: %ls", root.c_str());
        return;
    }
    if (!DirectoryExists(r)) {
        LogInfo(L"[Cleanup] Root not found, skip: %ls", r.c_str());
        return;
    }

    LogDebug(L"[Cleanup] Enumerating subdirectories of: %ls", r.c_str());

    std::wstring search = r;
    if (!search.empty() && search.back() != L'\\') search.push_back(L'\\');
    search.append(L"*");

    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
            LogWarn(L"[Cleanup] FindFirstFile failed on %ls (%lu)", r.c_str(), e);
        }
        return;
    }

    int deletedCount = 0;
    int failedCount = 0;
    do {
        if (IsDotOrDotDot(fd.cFileName)) continue;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;

        std::wstring child = r;
        if (!child.empty() && child.back() != L'\\') child.push_back(L'\\');
        child.append(fd.cFileName);

        LogDebug(L"[Cleanup] Deleting subdir: %ls (attrs=0x%08lX)", child.c_str(), fd.dwFileAttributes);
        DWORD dw = DeleteTreeNoFollow(child);
        if (dw == ERROR_SUCCESS) {
            LogInfo(L"[Cleanup] Deleted subdir: %ls", child.c_str());
            ++deletedCount;
        } else {
            LogWarn(L"[Cleanup] Failed to delete subdir: %ls (%lu)", child.c_str(), dw);
            ++failedCount;
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    LogInfo(L"[Cleanup] Subdirectory cleanup for %ls: %d deleted, %d failed", r.c_str(), deletedCount, failedCount);
}

static void CleanupAllowedPathSubdirs() {
    LogInfo(L"[Cleanup] Starting cleanup of %llu allowed path(s)...", (unsigned long long)AllowedPaths.size());
    for (const auto& p : AllowedPaths) {
        DeleteSubdirectoriesOfRoot(p);
    }
    LogInfo(L"[Cleanup] Allowed path subdirectory cleanup complete.");
}

static std::wstring JoinPath(const std::wstring& base, const std::wstring& leaf) {
    if (base.empty()) return leaf;
    if (leaf.empty()) return base;

    std::wstring out = base;
    if (out.back() != L'\\' && out.back() != L'/') {
        out.push_back(L'\\');
    }

    if (leaf.front() == L'\\' || leaf.front() == L'/') {
        out.append(leaf.substr(1));
    } else {
        out.append(leaf);
    }

    return out;
}

static std::wstring GetFileNamePart(const std::wstring& path) {
    if (path.empty()) return L"";
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

static std::wstring GetParentDir(const std::wstring& path) {
    if (path.empty()) return L"";

    std::wstring p = path;
    std::replace(p.begin(), p.end(), L'/', L'\\');

    while (p.size() > 3 && !p.empty() && p.back() == L'\\') {
        p.pop_back();
    }

    size_t pos = p.find_last_of(L'\\');
    if (pos == std::wstring::npos) return L"";
    if (pos == 2 && p[1] == L':') return p.substr(0, 3);
    if (pos == 0) return p.substr(0, 1);
    return p.substr(0, pos);
}

static std::wstring ParseImagePathFromCommandLine(PCWSTR cmdLine) {
    if (!cmdLine) return L"";

    const wchar_t* p = cmdLine;
    while (*p && IsSpace(*p)) ++p;
    if (*p == L'\0') return L"";

    if (*p == L'"') {
        ++p;
        const wchar_t* begin = p;
        while (*p && *p != L'"') ++p;
        return std::wstring(begin, p - begin);
    }

    const wchar_t* begin = p;
    while (*p && !IsSpace(*p)) ++p;
    return std::wstring(begin, p - begin);
}

static bool LooksLikeBunImage(const std::wstring& imagePath) {
    std::wstring name = ToLowerCopy(GetFileNamePart(imagePath));
    return name == L"bun" || name == L"bun.exe";
}

static bool CommandLineMentionsBun(PCWSTR cmdLine) {
    if (!cmdLine) return false;
    std::wstring lower = ToLowerCopy(std::wstring(cmdLine));

    if (lower.find(L"bun.exe") != std::wstring::npos) return true;
    if (lower == L"bun") return true;
    if (lower.rfind(L"bun ", 0) == 0) return true;
    if (lower.find(L" bun ") != std::wstring::npos) return true;
    if (lower.find(L"\\bun ") != std::wstring::npos) return true;
    if (lower.find(L"/bun ") != std::wstring::npos) return true;

    return false;
}

static bool LooksLikeOpenCodeImage(const std::wstring& imagePath) {
    std::wstring name = ToLowerCopy(GetFileNamePart(imagePath));
    return name == L"opencode" || name == L"opencode.exe";
}

static std::wstring GetFirstArgTokenLower(PCWSTR cmdLine) {
    if (!cmdLine) return L"";

    const wchar_t* p = cmdLine;
    while (*p && IsSpace(*p)) ++p;
    if (*p == L'\0') return L"";

    if (*p == L'"') {
        ++p;
        while (*p && *p != L'"') ++p;
        if (*p == L'"') ++p;
    } else {
        while (*p && !IsSpace(*p)) ++p;
    }

    while (*p && IsSpace(*p)) ++p;
    if (*p == L'\0') return L"";

    std::wstring token;
    if (*p == L'"') {
        ++p;
        const wchar_t* begin = p;
        while (*p && *p != L'"') ++p;
        token.assign(begin, p - begin);
    } else {
        const wchar_t* begin = p;
        while (*p && !IsSpace(*p)) ++p;
        token.assign(begin, p - begin);
    }

    return ToLowerCopy(token);
}

static bool IsOpenCodeTuiInvocation(PCWSTR cmdLine) {
    if (!cmdLine) return false;
    std::wstring image = ParseImagePathFromCommandLine(cmdLine);
    if (!LooksLikeOpenCodeImage(image)) return false;

    std::wstring sub = GetFirstArgTokenLower(cmdLine);
    if (sub.empty()) return true;

    if (sub == L"--help" || sub == L"-h" ||
        sub == L"--version" || sub == L"-v" ||
        sub == L"config" || sub == L"auth" ||
        sub == L"model" || sub == L"provider" ||
        sub == L"mcp" || sub == L"rules" ||
        sub == L"completion" || sub == L"doctor") {
        return false;
    }

    return true;
}

static bool IsConsoleInteractiveSession() {
    DWORD mode = 0;
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) return false;
    if (!GetConsoleMode(hIn, &mode)) return false;
    if (!GetConsoleMode(hOut, &mode)) return false;
    return true;
}

static void AutoEnableWaitForTuiIfNeeded() {
    if (WaitForExit) return;
    if (!ExeToLaunch) return;
    if (!IsConsoleInteractiveSession()) return;

    if (IsOpenCodeTuiInvocation(ExeToLaunch)) {
        WaitForExit = true;
        g_WaitAutoEnabled = true;
        LogWarn(L"wait=false but OpenCode TUI detected; auto-enabled wait=true so ConPTY can be used (fixes setRawMode errno=1).");
    }
}

// ========================================================================
// Shell Compatibility for AppContainer
// ========================================================================
// Forward declaration (defined later in file)
static void UpsertEnvOverride(const std::wstring& key, const std::wstring& value);

// MSYS2-based shells (Git Bash, Cygwin bash) cannot run inside AppContainer
// because they require creating kernel namespace objects under
// \BaseNamedObjects\msys-2.0* which is blocked by the sandbox.
// Detect and replace SHELL env var with cmd.exe automatically.
// ========================================================================
static bool IsMsys2OrCygwinPath(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring lower = ToLowerCopy(path);
    // Git for Windows: ...\Git\usr\bin\bash.exe, ...\Git\bin\bash.exe
    if (lower.find(L"\\git\\") != std::wstring::npos &&
        lower.find(L"bash") != std::wstring::npos) return true;
    // MSYS2: ...\msys64\usr\bin\bash.exe
    if (lower.find(L"\\msys") != std::wstring::npos) return true;
    // Cygwin: ...\cygwin64\bin\bash.exe
    if (lower.find(L"\\cygwin") != std::wstring::npos) return true;
    return false;
}

static void FixShellForAppContainer() {
    std::wstring currentShell = GetEnvVarCopy(L"SHELL");
    std::wstring comspec = GetEnvVarCopy(L"COMSPEC");
    std::wstring safeShell = comspec.empty() ? L"C:\\Windows\\System32\\cmd.exe" : comspec;

    // Case 1: SHELL points to MSYS2/Cygwin bash -> override with cmd.exe
    if (!currentShell.empty() && IsMsys2OrCygwinPath(currentShell)) {
        LogWarn(L"[ShellCompat] SHELL=%ls is MSYS2/Cygwin, incompatible with AppContainer.", currentShell.c_str());
        UpsertEnvOverride(L"SHELL", safeShell);
        UpsertEnvOverride(L"COMSPEC", safeShell);
        LogInfo(L"[ShellCompat] Override SHELL=%ls for AppContainer compatibility.", safeShell.c_str());
        return;
    }

    // Case 2: SHELL not set -> OpenCode/Node will search PATH and find bash.exe -> preempt
    if (currentShell.empty()) {
        UpsertEnvOverride(L"SHELL", safeShell);
        LogInfo(L"[ShellCompat] SHELL was empty, set to %ls for AppContainer compatibility.", safeShell.c_str());
        return;
    }

    LogDebug(L"[ShellCompat] SHELL=%ls appears safe, no override.", currentShell.c_str());
}

static bool ResolveSubstPath(const std::wstring& inputPath, std::wstring* resolvedPath) {
    if (!resolvedPath) return false;

    std::wstring p = NormalizePathForCompare(inputPath);
    if (p.size() < 2 || p[1] != L':' || !iswalpha(p[0])) {
        return false;
    }

    wchar_t drive[3] = { static_cast<wchar_t>(towupper(p[0])), L':', L'\0' };
    wchar_t target[4096] = {};
    DWORD n = QueryDosDeviceW(drive, target, _countof(target));
    if (n == 0) {
        return false;
    }

    std::wstring firstTarget(target);
    const std::wstring dosPrefix = L"\\??\\";
    if (firstTarget.rfind(dosPrefix, 0) != 0) {
        return false;
    }

    std::wstring mapped = firstTarget.substr(dosPrefix.size());
    if (mapped.size() < 2 || mapped[1] != L':') {
        return false;
    }

    std::wstring tail = p.substr(2);
    *resolvedPath = mapped + tail;
    return true;
}

static void ResolveExePathIfSubst() {
    if (!ExeToLaunch) return;

    std::wstring image = ParseImagePathFromCommandLine(ExeToLaunch);
    if (image.empty()) return;

    LogDebug(L"[SubstResolve] Checking if exe path is on SUBST drive: %ls", image.c_str());

    std::wstring resolved;
    if (ResolveSubstPath(image, &resolved)) {
        if (!PathEqualsInsensitive(image, resolved)) {
            LogInfo(L"[SubstResolve] Executable path is on a SUBST drive. Resolving '%ls' -> '%ls'", image.c_str(), resolved.c_str());

            const wchar_t* p = ExeToLaunch;
            while (*p && IsSpace(*p)) ++p;

            std::wstring argsSuffix;
            bool wasQuoted = false;

            if (*p == L'"') {
                wasQuoted = true;
                ++p;
                const wchar_t* end = p;
                while (*end && *end != L'"') ++end;
                if (*end == L'"') {
                    argsSuffix = (end + 1);
                } else {
                    argsSuffix = end;
                }
            } else {
                const wchar_t* end = p;
                while (*end && !IsSpace(*end)) ++end;
                argsSuffix = end;
            }

            std::wstring newCmd;
            bool needsQuotes = wasQuoted || (resolved.find(L' ') != std::wstring::npos);
            if (needsQuotes) newCmd = L"\"" + resolved + L"\"";
            else newCmd = resolved;

            newCmd += argsSuffix;

            g_CmdLineBuf.assign(newCmd.begin(), newCmd.end());
            g_CmdLineBuf.push_back(L'\0');
            ExeToLaunch = g_CmdLineBuf.data();
            LogInfo(L"[SubstResolve] New command line: %ls", ExeToLaunch);
        } else {
            LogDebug(L"[SubstResolve] Path already resolved, no change needed.");
        }
    } else {
        LogDebug(L"[SubstResolve] Not a SUBST drive or resolution not needed.");
    }
}

static void UpsertEnvOverride(const std::wstring& key, const std::wstring& value) {
    if (key.empty() || key.find(L'=') != std::wstring::npos) return;

    for (auto& kv : EnvOverrides) {
        if (IEquals(kv.name, key)) {
            LogDebug(L"[Env] Updating existing override: %ls = %ls (was: %ls)", key.c_str(), value.c_str(), kv.value.c_str());
            kv.value = value;
            return;
        }
    }

    LogDebug(L"[Env] Adding new override: %ls = %ls", key.c_str(), value.c_str());
    EnvOverrides.push_back(EnvKV{ key, value });
}

// ========================================================================
// Default OpenCode Environment Paths
// ========================================================================
static std::wstring GetExeDir();  // forward declaration (defined in INI Config section)

// Only set env var if NOT already present in EnvOverrides (user config takes priority)
static void SetEnvDefaultIfAbsent(const std::wstring& key, const std::wstring& value) {
    for (const auto& kv : EnvOverrides) {
        if (IEquals(kv.name, key)) {
            LogDebug(L"[EnvDefault] Skipping '%ls' (already set to '%ls')", key.c_str(), kv.value.c_str());
            return;
        }
    }
    LogInfo(L"[EnvDefault] Setting default: %ls = %ls", key.c_str(), value.c_str());
    EnvOverrides.push_back(EnvKV{ key, value });
}

static void ApplyDefaultOpenCodeEnvPaths() {
    std::wstring exeDir = GetExeDir();
    if (exeDir.empty()) return;

    // Remove trailing backslash for clean paths
    while (exeDir.size() > 3 && exeDir.back() == L'\\') exeDir.pop_back();

    std::wstring baseDir = JoinPath(exeDir, L"opencode");
    std::wstring workDir   = JoinPath(baseDir, L"work");
    std::wstring configDir = JoinPath(baseDir, L"config");
    std::wstring cacheDir  = JoinPath(baseDir, L"cache");
    std::wstring dataDir   = JoinPath(baseDir, L"data");
    std::wstring tempDir   = JoinPath(baseDir, L"temp");

    LogInfo(L"[EnvDefault] Setting up default OpenCode env paths under: %ls", exeDir.c_str());

    // Create directories
    CreateDirectoryW(baseDir.c_str(), nullptr);
    CreateDirectoryW(workDir.c_str(), nullptr);
    CreateDirectoryW(configDir.c_str(), nullptr);
    CreateDirectoryW(cacheDir.c_str(), nullptr);
    CreateDirectoryW(dataDir.c_str(), nullptr);
    CreateDirectoryW(tempDir.c_str(), nullptr);

    // Set environment variables (user config takes priority)
    SetEnvDefaultIfAbsent(L"HOME",            workDir);
    SetEnvDefaultIfAbsent(L"USERPROFILE",     workDir);
    SetEnvDefaultIfAbsent(L"APPDATA",         configDir);
    SetEnvDefaultIfAbsent(L"LOCALAPPDATA",    dataDir);
    SetEnvDefaultIfAbsent(L"TEMP",            tempDir);
    SetEnvDefaultIfAbsent(L"TMP",             tempDir);
    SetEnvDefaultIfAbsent(L"XDG_CONFIG_HOME", configDir);
    SetEnvDefaultIfAbsent(L"XDG_CACHE_HOME",  cacheDir);
    SetEnvDefaultIfAbsent(L"XDG_DATA_HOME",   dataDir);
    SetEnvDefaultIfAbsent(L"OPENCODE_CONFIG", JoinPath(baseDir, L"opencode.json"));

    // Auto-add all subdirs to AllowedPaths
    std::wstring dirs[] = { baseDir, workDir, configDir, cacheDir, dataDir, tempDir };
    for (const auto& d : dirs) {
        if (AddAllowedPathUnique(d)) {
            LogInfo(L"[EnvDefault] Auto-allowed path: %ls", d.c_str());
        }
    }

    LogInfo(L"[EnvDefault] Default OpenCode env paths applied.");
}

static void ApplyBunOpenTuiCompatibility() {
    if (!ExeToLaunch) return;

    std::wstring imagePath = ParseImagePathFromCommandLine(ExeToLaunch);
    bool bunDetected = LooksLikeBunImage(imagePath) || CommandLineMentionsBun(ExeToLaunch);
    if (!bunDetected) {
        LogDebug(L"[BunCompat] Not a Bun invocation, skipping compatibility setup.");
        return;
    }

    LogInfo(L"[BunCompat] Bun runtime detected in command line.");

    std::wstring bunInstall = TrimCopy(GetEnvVarCopy(L"BUN_INSTALL"));
    if (bunInstall.empty() && !imagePath.empty()) {
        std::wstring imageDir = GetParentDir(imagePath);
        if (IEquals(GetFileNamePart(imageDir), L"bin")) {
            bunInstall = GetParentDir(imageDir);
            LogDebug(L"[BunCompat] Inferred BUN_INSTALL from image path: %ls", bunInstall.c_str());
        }
    }

    if (bunInstall.empty()) {
        LogWarn(L"[BunCompat] bun detected, but BUN_INSTALL is empty. Skip auto path fix.");
        return;
    }

    LogInfo(L"[BunCompat] BUN_INSTALL = %ls", bunInstall.c_str());
    bool changed = false;

    auto applyBase = [&](const std::wstring& base, PCWSTR sourceTag) {
        if (base.empty()) return;

        std::wstring rootPath = JoinPath(base, L"root");
        std::wstring binPath = JoinPath(base, L"bin");

        LogDebug(L"%ls Checking paths: root=%ls, bin=%ls", sourceTag, rootPath.c_str(), binPath.c_str());

        if (DirectoryExists(rootPath)) {
            if (AddAllowedPathUnique(rootPath)) {
                LogInfo(L"%ls Auto allow path: %ls", sourceTag, rootPath.c_str());
                changed = true;
            }
            if (AddPathPrependUnique(rootPath)) {
                LogInfo(L"%ls Auto PATH prepend: %ls", sourceTag, rootPath.c_str());
                changed = true;
            }
        } else {
            LogDebug(L"%ls root path does not exist: %ls", sourceTag, rootPath.c_str());
        }

        if (DirectoryExists(binPath)) {
            if (AddPathPrependUnique(binPath)) {
                LogInfo(L"%ls Auto PATH prepend: %ls", sourceTag, binPath.c_str());
                changed = true;
            }
        } else {
            LogDebug(L"%ls bin path does not exist: %ls", sourceTag, binPath.c_str());
        }
    };

    applyBase(bunInstall, L"[BunCompat]");

    std::wstring resolvedInstall;
    if (ResolveSubstPath(bunInstall, &resolvedInstall) &&
        !PathEqualsInsensitive(bunInstall, resolvedInstall) &&
        DirectoryExists(resolvedInstall)) {
        UpsertEnvOverride(L"BUN_INSTALL", resolvedInstall);
        LogInfo(L"[BunCompat] Remap BUN_INSTALL for child: %ls -> %ls", bunInstall.c_str(), resolvedInstall.c_str());
        applyBase(resolvedInstall, L"[BunCompat]");
    }

    if (changed) {
        LogInfo(L"[BunCompat] Applied OpenTUI runtime compatibility settings.");
    } else {
        LogInfo(L"[BunCompat] No additional Bun path changes were needed.");
    }
}

// ========================================================================
// Capability / SID helpers
// ========================================================================
static void FreeSidArray(PSID* sids, ULONG count) {
    if (!sids) return;
    for (ULONG i = 0; i < count; i++) {
        if (sids[i]) {
            LocalFree(sids[i]);
            sids[i] = nullptr;
        }
    }
    LocalFree(sids);
}

static void PrintUsage() {
    wprintf(L"LaunchAppContainer.exe Usage:\r\n");
    wprintf(L"\t-m Moniker -i ExeToLaunch -c Cap1;Cap2 -a Path1;Path2 -e K1=V1;K2=V2 -p Dir1;Dir2 -s -w -r -l -k -x\r\n");
    wprintf(L"\r\n");
    wprintf(L"Required:\r\n");
    wprintf(L"\t-i : Command line of exe to launch\r\n");
    wprintf(L"\t-m : Package moniker\r\n");
    wprintf(L"\r\n");
    wprintf(L"Optional:\r\n");
    wprintf(L"\t-c : Capabilities (or SIDs)\r\n");
    wprintf(L"\t-d : Display name for profile\r\n");
    wprintf(L"\t-a : Semicolon-separated directories to grant (F)\r\n");
    wprintf(L"\t-e : Semicolon-separated env pairs (K=V;K2=V2)\r\n");
    wprintf(L"\t-p : Semicolon-separated path prepend list\r\n");
    wprintf(L"\t-s : Skip setting Low Integrity on -a paths\r\n");
    wprintf(L"\t-w : Wait for child exit\r\n");
    wprintf(L"\t-r : Retain AppContainer profile after exit\r\n");
    wprintf(L"\t-l : Launch as LPAC\r\n");
    wprintf(L"\t-k : Enable win32k lockdown\r\n");
    wprintf(L"\t-x : Cleanup: recursively delete subdirectories under -a paths after exit (keep roots)\r\n");
    wprintf(L"\t-g : Enable logging (console + file)\r\n");
    wprintf(L"\r\n");
    wprintf(L"Notes:\r\n");
    wprintf(L"\t- Child shares current console window.\r\n");
    wprintf(L"\t- config.ini [App] is auto-loaded when no CLI args.\r\n");
    wprintf(L"\t- For bun/bun.exe, %%BUN_INSTALL%%\\root is auto-added to allowPaths and PATH.\r\n");
    wprintf(L"\r\n");
    wprintf(L"Network Filter (config.ini only):\r\n");
    wprintf(L"\tnetworkFilterEnabled = true|false  (enable domain-based network filtering)\r\n");
    wprintf(L"\tnetworkFilterPort = 8080           (local proxy port)\r\n");
    wprintf(L"\tnetworkFilterAllowedUrls = *.example.com;api.other.com  (allowed domains)\r\n");
}

// ========================================================================
// Argument / Config Parsing
// ========================================================================
static bool ParseCapabilityList(WCHAR* caps) {
    if (!caps) return true;

    WCHAR* ctx = nullptr;
    for (WCHAR* tok = wcstok_s(caps, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
        std::wstring cap = TrimCopy(tok);
        if (cap.empty()) continue;

        SID_AND_ATTRIBUTES sidInfo{};
        sidInfo.Attributes = SE_GROUP_ENABLED;

        if (ConvertStringSidToSidW(cap.c_str(), &sidInfo.Sid)) {
            LogDebug(L"[Caps] Parsed SID string: %ls", cap.c_str());
            CapabilityList.emplace_back(sidInfo);
            continue;
        }

        PSID* capGroupSids = nullptr;
        DWORD capGroupSidsLen = 0;
        PSID* capSids = nullptr;
        DWORD capSidsLen = 0;

        if (DeriveCapabilitySidsFromName(cap.c_str(), &capGroupSids, &capGroupSidsLen, &capSids, &capSidsLen)) {
            LogDebug(L"[Caps] Derived %lu capability SIDs from name: %ls", capSidsLen, cap.c_str());
            for (DWORD i = 0; i < capSidsLen; ++i) {
                CapabilityList.emplace_back(SID_AND_ATTRIBUTES{ capSids[i], SE_GROUP_ENABLED });
            }
            FreeSidArray(capGroupSids, capGroupSidsLen);
            LocalFree(capSids);
            continue;
        }

        LogError(L"Failed to parse capability token: %ls (GetLastError=%lu)", cap.c_str(), GetLastError());
        return false;
    }

    return true;
}

static bool ParseAllowedPathList(WCHAR* paths) {
    if (!paths) return true;

    WCHAR* ctx = nullptr;
    for (WCHAR* tok = wcstok_s(paths, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
        std::wstring p = TrimCopy(tok);
        if (!p.empty()) {
            if (AddAllowedPathUnique(p)) {
                LogInfo(L"Allowed path added: %ls", p.c_str());
            } else {
                LogDebug(L"Allowed path ignored (duplicate): %ls", p.c_str());
            }
        }
    }
    return true;
}

static bool ParseEnvList(WCHAR* env) {
    if (!env) return true;

    WCHAR* ctx = nullptr;
    for (WCHAR* tok = wcstok_s(env, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
        std::wstring pair = TrimCopy(tok);
        if (pair.empty()) continue;

        size_t eq = pair.find(L'=');
        std::wstring k = TrimCopy(eq == std::wstring::npos ? pair : pair.substr(0, eq));
        std::wstring v = TrimCopy(eq == std::wstring::npos ? L"" : pair.substr(eq + 1));

        if (!k.empty() && k.find(L'=') == std::wstring::npos) {
            EnvOverrides.push_back(EnvKV{ k, v });
            LogInfo(L"Env override added: %ls = %ls", k.c_str(), v.c_str());
        } else {
            LogWarn(L"Ignored invalid env token: %ls", pair.c_str());
        }
    }

    return true;
}

static bool ParsePathPrependList(WCHAR* paths) {
    if (!paths) return true;

    WCHAR* ctx = nullptr;
    for (WCHAR* tok = wcstok_s(paths, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
        std::wstring p = TrimCopy(tok);
        if (!p.empty()) {
            if (AddPathPrependUnique(p)) {
                LogInfo(L"PATH prepend added: %ls", p.c_str());
            } else {
                LogDebug(L"PATH prepend ignored (duplicate): %ls", p.c_str());
            }
        }
    }

    return true;
}

static bool ParseCapabilityListFromArg(PCWSTR arg) {
    if (!arg) return true;
    std::vector<wchar_t> buf(arg, arg + wcslen(arg));
    buf.push_back(L'\0');
    return ParseCapabilityList(buf.data());
}

static bool ParseAllowedPathListFromArg(PCWSTR arg) {
    if (!arg) return true;
    std::vector<wchar_t> buf(arg, arg + wcslen(arg));
    buf.push_back(L'\0');
    return ParseAllowedPathList(buf.data());
}

static bool ParseEnvListFromArg(PCWSTR arg) {
    if (!arg) return true;
    std::vector<wchar_t> buf(arg, arg + wcslen(arg));
    buf.push_back(L'\0');
    return ParseEnvList(buf.data());
}

static bool ParsePathPrependListFromArg(PCWSTR arg) {
    if (!arg) return true;
    std::vector<wchar_t> buf(arg, arg + wcslen(arg));
    buf.push_back(L'\0');
    return ParsePathPrependList(buf.data());
}

static bool ParseArguments(int argc, WCHAR** argv) {
    LogDebug(L"[Args] Parsing %d command-line arguments...", argc);
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != L'-' && argv[i][0] != L'/') {
            LogDebug(L"[Args] Skipping non-option arg[%d]: %ls", i, argv[i]);
            continue;
        }

        LogDebug(L"[Args] Processing arg[%d]: %ls", i, argv[i]);
        switch (argv[i][1]) {
        case L'i':
            if (i + 1 >= argc) { PrintUsage(); return false; }
            ExeToLaunch = argv[++i];
            LogInfo(L"[Args] exe = %ls", ExeToLaunch);
            break;
        case L'm':
            if (i + 1 >= argc) { PrintUsage(); return false; }
            PackageMoniker = argv[++i];
            LogInfo(L"[Args] moniker = %ls", PackageMoniker.c_str());
            break;
        case L'c':
            if (i + 1 >= argc) { PrintUsage(); return false; }
            if (!ParseCapabilityListFromArg(argv[++i])) return false;
            break;
        case L'd':
            if (i + 1 >= argc) { PrintUsage(); return false; }
            PackageDisplayName = argv[++i];
            LogInfo(L"[Args] displayName = %ls", PackageDisplayName.c_str());
            break;
        case L'a':
            if (i + 1 >= argc) { PrintUsage(); return false; }
            if (!ParseAllowedPathListFromArg(argv[++i])) return false;
            break;
        case L'e':
            if (i + 1 >= argc) { PrintUsage(); return false; }
            if (!ParseEnvListFromArg(argv[++i])) return false;
            break;
        case L'p':
            if (i + 1 >= argc) { PrintUsage(); return false; }
            if (!ParsePathPrependListFromArg(argv[++i])) return false;
            break;
        case L's': PathLowIntegrity = false; LogDebug(L"[Args] lowIntegrity disabled"); break;
        case L'w': WaitForExit = true; LogDebug(L"[Args] wait=true"); break;
        case L'r': RetainProfile = true; LogDebug(L"[Args] retainProfile=true"); break;
        case L'l': LaunchAsLpac = true; LogDebug(L"[Args] lpac=true"); break;
        case L'k': NoWin32k = true; LogDebug(L"[Args] noWin32k=true"); break;
        case L'x': CleanupAllowedSubdirs = true; LogDebug(L"[Args] cleanupSubdirs=true"); break;
        case L'g': g_LogEnabled = true; LogDebug(L"[Args] log=true"); break;
        default:
            LogWarn(L"[Args] Unknown option: %ls", argv[i]);
            break;
        }
    }

    LogInfo(L"[Args] Parse complete: %llu capabilities, %llu allowed paths, %llu env overrides, %llu path prepends",
            (unsigned long long)CapabilityList.size(), (unsigned long long)AllowedPaths.size(),
            (unsigned long long)EnvOverrides.size(), (unsigned long long)PathPrependEntries.size());
    return true;
}

// ========================================================================
// AppContainer Profile Management
// ========================================================================
static DWORD CreateAppContainerProfileWithMoniker(PSID* pAppContainerSid) {
    g_ProfileWasCreated = false;
    *pAppContainerSid = nullptr;

    PCWSTR display = PackageDisplayName.empty() ? PackageMoniker.c_str() : PackageDisplayName.c_str();
    LogInfo(L"[Profile] Creating AppContainer profile: moniker='%ls', display='%ls', caps=%llu",
            PackageMoniker.c_str(), display, (unsigned long long)CapabilityList.size());

    PSID packageSid = nullptr;
    HRESULT hr = CreateAppContainerProfile(
        PackageMoniker.c_str(), display, display,
        CapabilityList.data(),
        static_cast<DWORD>(CapabilityList.size()),
        &packageSid);

    if (SUCCEEDED(hr)) {
        g_ProfileWasCreated = true;
        *pAppContainerSid = packageSid;

        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(packageSid, &sidStr)) {
            LogInfo(L"[Profile] Created new profile. SID=%ls", sidStr);
            LocalFree(sidStr);
        } else {
            LogInfo(L"[Profile] Created new profile successfully.");
        }
        return ERROR_SUCCESS;
    }

    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        LogInfo(L"[Profile] Profile already exists, deriving SID...");
        hr = DeriveAppContainerSidFromAppContainerName(PackageMoniker.c_str(), &packageSid);
        if (SUCCEEDED(hr)) {
            *pAppContainerSid = packageSid;
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(packageSid, &sidStr)) {
                LogInfo(L"[Profile] Reusing existing profile. SID=%ls", sidStr);
                LocalFree(sidStr);
            }
            return ERROR_SUCCESS;
        }
        DWORD err = HRESULT_CODE(hr);
        LogError(L"[Profile] DeriveAppContainerSidFromAppContainerName failed: hr=0x%08lX, err=%lu", (DWORD)hr, err);
        return err;
    }

    DWORD err = HRESULT_CODE(hr);
    LogError(L"[Profile] CreateAppContainerProfile failed: hr=0x%08lX, err=%lu", (DWORD)hr, err);
    return err;
}

static DWORD DeleteAppContainerProfileWithMoniker() {
    LogInfo(L"[Profile] Deleting AppContainer profile: %ls", PackageMoniker.c_str());
    HRESULT hr = DeleteAppContainerProfile(PackageMoniker.c_str());
    if (FAILED(hr)) {
        DWORD err = HRESULT_CODE(hr);
        LogWarn(L"[Profile] DeleteAppContainerProfile failed: hr=0x%08lX, err=%lu", (DWORD)hr, err);
        return err;
    }
    LogInfo(L"[Profile] Profile deleted successfully.");
    return ERROR_SUCCESS;
}

// ========================================================================
// Security / ACL Management
// ========================================================================
static DWORD GrantFullControlToSidOnPath(PCWSTR path, PSID sid) {
    LogDebug(L"[ACL] GrantFullControl on: %ls", path);
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL oldDacl = nullptr;

    DWORD dw = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                     nullptr, nullptr, &oldDacl, nullptr, &sd);
    if (dw != ERROR_SUCCESS) {
        LogError(L"[ACL] GetNamedSecurityInfoW failed on %ls: err=%lu", path, dw);
        return dw;
    }

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = FILE_ALL_ACCESS;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    BuildTrusteeWithSidW(&ea.Trustee, sid);

    PACL newDacl = nullptr;
    dw = SetEntriesInAclW(1, &ea, oldDacl, &newDacl);
    if (dw != ERROR_SUCCESS) {
        LogError(L"[ACL] SetEntriesInAclW failed on %ls: err=%lu", path, dw);
        if (sd) LocalFree(sd);
        return dw;
    }

    dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
                               DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
    if (dw != ERROR_SUCCESS) {
        LogError(L"[ACL] SetNamedSecurityInfoW (DACL) failed on %ls: err=%lu", path, dw);
    } else {
        LogDebug(L"[ACL] Successfully granted FILE_ALL_ACCESS on: %ls", path);
    }

    if (newDacl) LocalFree(newDacl);
    if (sd) LocalFree(sd);
    return dw;
}

static DWORD SetLowIntegrityLabel(PCWSTR path) {
    LogDebug(L"[ACL] Setting Low Integrity label on: %ls", path);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"S:(ML;;NW;;;LW)", SDDL_REVISION_1, &sd, nullptr)) {
        DWORD err = GetLastError();
        LogError(L"[ACL] ConvertStringSecurityDescriptorToSecurityDescriptorW failed: err=%lu", err);
        return err;
    }

    PACL sacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted)) {
        DWORD err = GetLastError();
        LogError(L"[ACL] GetSecurityDescriptorSacl failed: err=%lu", err);
        LocalFree(sd);
        return err;
    }

    DWORD dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
                                     LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, sacl);
    if (dw != ERROR_SUCCESS) {
        LogWarn(L"[ACL] SetNamedSecurityInfoW (SACL/LowIntegrity) failed on %ls: err=%lu (needs elevation)", path, dw);
    } else {
        LogDebug(L"[ACL] Low Integrity label set successfully on: %ls", path);
    }

    LocalFree(sd);
    return dw;
}

static DWORD RestoreDaclWithProtection(const SavedSecurity& ss) {
    if (!ss.hasDacl) return ERROR_INVALID_PARAMETER;
    DWORD flags = DACL_SECURITY_INFORMATION;
    flags |= ss.daclProtected ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
    return SetNamedSecurityInfoW(const_cast<LPWSTR>(ss.path.c_str()), SE_FILE_OBJECT,
                                 flags, nullptr, nullptr, ss.dacl, nullptr);
}

static DWORD SaveOriginalSecurityForPath(PCWSTR path) {
    LogDebug(L"[Security] Saving original security descriptor for: %ls", path);
    SavedSecurity ss{};
    ss.path = path;

    DWORD daclErr = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                          nullptr, nullptr, &ss.dacl, nullptr, &ss.sdDacl);
    if (daclErr == ERROR_SUCCESS) {
        ss.hasDacl = true;
        SECURITY_DESCRIPTOR_CONTROL ctrl = 0;
        DWORD rev = 0;
        if (GetSecurityDescriptorControl(ss.sdDacl, &ctrl, &rev)) {
            ss.daclProtected = (ctrl & SE_DACL_PROTECTED) != 0;
        }
        LogInfo(L"[Security] Backed up DACL for %ls (protected=%d, revision=%lu)", path, ss.daclProtected ? 1 : 0, rev);
    } else {
        LogWarn(L"[Security] Failed to backup DACL for %ls (err=%lu)", path, daclErr);
    }

    DWORD saclErr = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                                          nullptr, nullptr, nullptr, &ss.sacl, &ss.sdSacl);
    if (saclErr == ERROR_SUCCESS) {
        ss.hasSacl = true;
        LogInfo(L"[Security] Backed up Label SACL for %ls", path);
    } else {
        LogWarn(L"[Security] Failed to backup Label SACL for %ls (err=%lu)", path, saclErr);
    }

    g_SavedSecurity.emplace_back(ss);
    return (daclErr == ERROR_SUCCESS || saclErr == ERROR_SUCCESS) ? ERROR_SUCCESS
           : (daclErr != ERROR_SUCCESS ? daclErr : saclErr);
}

static void RestoreSavedSecurity() {
    LogInfo(L"[Revert] Restoring original security on %llu path(s)...", (unsigned long long)g_SavedSecurity.size());
    int restoredDacl = 0, restoredSacl = 0, failedDacl = 0, failedSacl = 0;

    for (auto& ss : g_SavedSecurity) {
        if (ss.hasDacl) {
            DWORD dw = RestoreDaclWithProtection(ss);
            if (dw == ERROR_SUCCESS) {
                LogInfo(L"[Revert] Restored DACL on %ls (protected=%d)", ss.path.c_str(), ss.daclProtected ? 1 : 0);
                ++restoredDacl;
            } else {
                LogWarn(L"[Revert] Failed to restore DACL on %ls (err=%lu)", ss.path.c_str(), dw);
                ++failedDacl;
            }
        }
        if (ss.hasSacl) {
            DWORD dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(ss.path.c_str()), SE_FILE_OBJECT,
                                             LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, ss.sacl);
            if (dw == ERROR_SUCCESS) {
                LogInfo(L"[Revert] Restored Label SACL on %ls", ss.path.c_str());
                ++restoredSacl;
            } else {
                LogWarn(L"[Revert] Failed to restore Label SACL on %ls (err=%lu)", ss.path.c_str(), dw);
                ++failedSacl;
            }
        }
        if (ss.sdDacl) { LocalFree(ss.sdDacl); ss.sdDacl = nullptr; }
        if (ss.sdSacl) { LocalFree(ss.sdSacl); ss.sdSacl = nullptr; }
    }
    g_SavedSecurity.clear();

    LogInfo(L"[Revert] Security restore complete: DACL restored=%d failed=%d, SACL restored=%d failed=%d",
            restoredDacl, failedDacl, restoredSacl, failedSacl);
}

static void RestoreSavedSecurityOnce() {
    if (InterlockedCompareExchange(&g_RestoreDone, 1, 0) != 0) {
        LogDebug(L"[Revert] RestoreSavedSecurityOnce already executed, skipping.");
        return;
    }
    if (InterlockedCompareExchange(&g_PathAclModified, 0, 0) == 1) {
        RestoreSavedSecurity();
    } else {
        LogDebug(L"[Revert] No path ACLs were modified, nothing to restore.");
    }
}

static void GrantAccessToAllowedPaths(PSID appContainerSid) {
    LogInfo(L"[Permissions] Granting access to %llu allowed path(s)...", (unsigned long long)AllowedPaths.size());
    int grantedCount = 0, skippedCount = 0, failedCount = 0;

    for (const auto& path : AllowedPaths) {
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            wprintf(L"[Skip] Path not found: %ls (err=%lu)\r\n", path.c_str(), GetLastError());
            LogWarn(L"[Permissions] Skip path (not found): %ls (err=%lu)", path.c_str(), GetLastError());
            ++skippedCount;
            continue;
        }
        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            wprintf(L"[Skip] Not a directory: %ls (attrs=0x%08lX)\r\n", path.c_str(), attrs);
            LogWarn(L"[Permissions] Skip path (not directory): %ls (attrs=0x%08lX)", path.c_str(), attrs);
            ++skippedCount;
            continue;
        }

        LogDebug(L"[Permissions] Processing path: %ls (attrs=0x%08lX)", path.c_str(), attrs);

        SaveOriginalSecurityForPath(path.c_str());
        SavedSecurity* backup = g_SavedSecurity.empty() ? nullptr : &g_SavedSecurity.back();
        bool modifiedThisPath = false;

        if (backup && backup->hasDacl) {
            DWORD dw = GrantFullControlToSidOnPath(path.c_str(), appContainerSid);
            if (dw == ERROR_SUCCESS) {
                wprintf(L"[OK] Granted (F) to %ls\r\n", path.c_str());
                LogInfo(L"[Permissions] Granted FILE_ALL_ACCESS on %ls", path.c_str());
                modifiedThisPath = true;
            } else {
                wprintf(L"[Warn] Grant (F) failed on %ls (%lu)\r\n", path.c_str(), dw);
                LogWarn(L"[Permissions] Grant (F) failed on %ls (err=%lu)", path.c_str(), dw);
                ++failedCount;
            }
        }

        if (PathLowIntegrity && backup && backup->hasSacl) {
            DWORD dw = SetLowIntegrityLabel(path.c_str());
            if (dw == ERROR_SUCCESS) {
                wprintf(L"[OK] Low Integrity set on %ls\r\n", path.c_str());
                LogInfo(L"[Permissions] Low Integrity set on %ls", path.c_str());
                modifiedThisPath = true;
            } else {
                wprintf(L"[Warn] Set Low Integrity failed on %ls (%lu)\r\n", path.c_str(), dw);
                if (dw == ERROR_ACCESS_DENIED)
                    LogWarn(L"[Permissions] Set Low Integrity DENIED on %ls. Run elevated or set lowIntegrityOnPaths=false.", path.c_str());
                else
                    LogWarn(L"[Permissions] Set Low Integrity failed on %ls (err=%lu)", path.c_str(), dw);
                ++failedCount;
            }
        }

        if (modifiedThisPath) {
            InterlockedExchange(&g_PathAclModified, 1);
            ++grantedCount;
        } else {
            if (!g_SavedSecurity.empty()) {
                auto& ss = g_SavedSecurity.back();
                if (ss.sdDacl) { LocalFree(ss.sdDacl); ss.sdDacl = nullptr; }
                if (ss.sdSacl) { LocalFree(ss.sdSacl); ss.sdSacl = nullptr; }
                g_SavedSecurity.pop_back();
            }
        }
    }

    LogInfo(L"[Permissions] Access grant summary: granted=%d, skipped=%d, failed=%d (total paths=%llu)",
            grantedCount, skippedCount, failedCount, (unsigned long long)AllowedPaths.size());
}

// ========================================================================
// ConPTY Support
// ========================================================================
static bool InitConPtyApi() {
    if (g_ConPtyAvailable) return true;
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) {
        LogWarn(L"[ConPTY] GetModuleHandleW(kernel32.dll) failed.");
        return false;
    }
    g_pfnCreatePC = (FnCreatePseudoConsole)GetProcAddress(hK32, "CreatePseudoConsole");
    g_pfnClosePC  = (FnClosePseudoConsole) GetProcAddress(hK32, "ClosePseudoConsole");
    g_ConPtyAvailable = (g_pfnCreatePC != nullptr && g_pfnClosePC != nullptr);
    if (!g_ConPtyAvailable) {
        LogWarn(L"[ConPTY] CreatePseudoConsole not available on this OS.");
    } else {
        LogDebug(L"[ConPTY] API loaded: CreatePseudoConsole=%p, ClosePseudoConsole=%p",
                 (void*)g_pfnCreatePC, (void*)g_pfnClosePC);
    }
    return g_ConPtyAvailable;
}

static COORD GetCurrentConsoleSize() {
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(hOut, &csbi)) {
        COORD sz;
        sz.X = csbi.srWindow.Right  - csbi.srWindow.Left + 1;
        sz.Y = csbi.srWindow.Bottom - csbi.srWindow.Top  + 1;
        LogDebug(L"[ConPTY] Console size: %dx%d", sz.X, sz.Y);
        return sz;
    }
    COORD fallback;
    fallback.X = 120;
    fallback.Y = 30;
    LogDebug(L"[ConPTY] Using fallback console size: %dx%d", fallback.X, fallback.Y);
    return fallback;
}

struct InputRelayCtx {
    HANDLE hPipeWrite;
    HANDLE hStopEvent;
};

static DWORD WINAPI ConPtyInputRelay(LPVOID param) {
    InputRelayCtx* ctx = static_cast<InputRelayCtx*>(param);
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    char buf[4096];
    DWORD totalRelayed = 0;
    for (;;) {
        HANDLE waits[2] = { hStdin, ctx->hStopEvent };
        DWORD wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wr != WAIT_OBJECT_0) break;
        DWORD bytesRead = 0;
        if (!ReadFile(hStdin, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0) break;
        DWORD totalWritten = 0;
        while (totalWritten < bytesRead) {
            DWORD written = 0;
            if (!WriteFile(ctx->hPipeWrite, buf + totalWritten,
                           bytesRead - totalWritten, &written, nullptr)) goto done;
            totalWritten += written;
        }
        totalRelayed += bytesRead;
    }
done:
    LogDebug(L"[ConPTY] Input relay thread exiting. Total bytes relayed: %lu", totalRelayed);
    return 0;
}

static DWORD WINAPI ConPtyOutputRelay(LPVOID param) {
    HANDLE hPipeRead = static_cast<HANDLE>(param);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    char buf[4096];
    DWORD totalRelayed = 0;
    for (;;) {
        DWORD bytesRead = 0;
        if (!ReadFile(hPipeRead, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0) break;
        DWORD totalWritten = 0;
        while (totalWritten < bytesRead) {
            DWORD written = 0;
            if (!WriteFile(hStdout, buf + totalWritten,
                           bytesRead - totalWritten, &written, nullptr)) goto done;
            totalWritten += written;
        }
        totalRelayed += bytesRead;
    }
done:
    LogDebug(L"[ConPTY] Output relay thread exiting. Total bytes relayed: %lu", totalRelayed);
    return 0;
}

// Forward declaration (defined later, needed by BunVFS)
static std::wstring GetExeDir();

// ========================================================================
// Bun Standalone Virtual Drive (B:\~BUN) Support
// ========================================================================
// Bun standalone executables embed native DLLs (like opentui) and serve
// them through a virtual B: drive created via DefineDosDeviceW() at startup.
// AppContainer blocks this call, so the child gets error 126 on LoadLibrary.
//
// Solution: the PARENT process (not sandboxed) extracts the embedded DLL
// from the opencode.exe binary, places it in a real staging directory that
// mirrors B:\~BUN\root\<dllname>, then uses DefineDosDeviceW() to create
// a session-visible B: drive mapping before launching the child.
// ========================================================================

// Search binary for ASCII filename matching "opentui-XXXX.dll"
static std::wstring FindDllNameInBinary(const BYTE* data, size_t dataSize) {
    LogDebug(L"[BunVFS] Scanning %llu bytes for DLL name pattern 'opentui-*.dll'...",
             (unsigned long long)dataSize);
    const char* pat = "opentui-";
    size_t patLen = 8;
    int candidateCount = 0;

    for (size_t i = 0; i + patLen + 4 < dataSize; ++i) {
        if (memcmp(data + i, pat, patLen) != 0) continue;

        ++candidateCount;
        size_t j = i + patLen;
        while (j < dataSize && j - i < 80) {
            BYTE ch = data[j];
            if (ch == '.') break;
            if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
                ++j;
            } else {
                break;
            }
        }

        if (j + 4 <= dataSize && memcmp(data + j, ".dll", 4) == 0) {
            size_t nameLen = (j + 4) - i;
            std::string name(reinterpret_cast<const char*>(data + i), nameLen);
            std::wstring wname(name.begin(), name.end());
            LogInfo(L"[BunVFS] Found DLL name at offset 0x%llX: '%ls' (scanned %d candidates)",
                    (unsigned long long)i, wname.c_str(), candidateCount);
            return wname;
        } else {
            LogDebug(L"[BunVFS] Candidate #%d at offset 0x%llX did not end with '.dll', skipping.",
                     candidateCount, (unsigned long long)i);
        }
    }

    LogWarn(L"[BunVFS] DLL name pattern not found after scanning %d candidates in %llu bytes.",
            candidateCount, (unsigned long long)dataSize);
    return L"";
}

// Convert an RVA (Relative Virtual Address) to a file offset using the section table.
// Returns 0 on failure. The PE base pointer must point to a valid MZ header.
static DWORD RvaToFileOffset(const BYTE* peBase, size_t peSize, DWORD rva) {
    if (peSize < 0x200 || rva == 0) return 0;

    DWORD peOff = *reinterpret_cast<const DWORD*>(peBase + 0x3C);
    if (peOff + 4 + 20 > peSize) return 0;

    size_t coffOff = peOff + 4;
    WORD numSections = *reinterpret_cast<const WORD*>(peBase + coffOff + 2);
    WORD optSize     = *reinterpret_cast<const WORD*>(peBase + coffOff + 16);
    size_t secTableOff = coffOff + 20 + optSize;

    if (numSections > 96 || secTableOff + numSections * 40 > peSize) return 0;

    for (WORD s = 0; s < numSections; ++s) {
        size_t sh = secTableOff + s * 40;
        DWORD secVA      = *reinterpret_cast<const DWORD*>(peBase + sh + 12);
        DWORD secRawSize = *reinterpret_cast<const DWORD*>(peBase + sh + 16);
        DWORD secRawPtr  = *reinterpret_cast<const DWORD*>(peBase + sh + 20);
        DWORD secVSize   = *reinterpret_cast<const DWORD*>(peBase + sh + 8);

        // Use the larger of VirtualSize and SizeOfRawData for bounds
        DWORD secExtent = (secRawSize > secVSize) ? secRawSize : secVSize;
        if (rva >= secVA && rva < secVA + secExtent) {
            DWORD offset = secRawPtr + (rva - secVA);
            if (offset < peSize) return offset;
        }
    }

    // RVA might be in headers (before first section)
    DWORD sizeOfHeaders = 0;
    size_t optOff = coffOff + 20;
    if (optOff + 64 <= peSize) {
        sizeOfHeaders = *reinterpret_cast<const DWORD*>(peBase + optOff + 60);
    }
    if (rva < sizeOfHeaders && rva < peSize) return rva;

    return 0;
}

// Check if a PE DLL (raw bytes in memory) exports a specific symbol name.
// Returns true if the symbol is found in the export name table.
// Also returns the total number of exported names via outExportCount (if non-null).
static bool PEDllExportsSymbol(const BYTE* peBase, size_t peSize,
                                const char* symbolName,
                                int* outExportCount = nullptr) {
    if (outExportCount) *outExportCount = 0;
    if (!peBase || peSize < 0x200 || !symbolName) return false;
    if (peBase[0] != 'M' || peBase[1] != 'Z') return false;

    DWORD peOff = *reinterpret_cast<const DWORD*>(peBase + 0x3C);
    if (peOff + 4 + 20 > peSize) return false;

    size_t coffOff = peOff + 4;
    WORD optSize = *reinterpret_cast<const WORD*>(peBase + coffOff + 16);
    size_t optOff = coffOff + 20;
    if (optOff + optSize > peSize) return false;

    WORD magic = *reinterpret_cast<const WORD*>(peBase + optOff);
    DWORD numDataDirs = 0;
    size_t dataDirOff = 0;
    if (magic == 0x010B) {       // PE32
        if (optSize < 96) return false;
        numDataDirs = *reinterpret_cast<const DWORD*>(peBase + optOff + 92);
        dataDirOff = optOff + 96;
    } else if (magic == 0x020B) { // PE32+
        if (optSize < 112) return false;
        numDataDirs = *reinterpret_cast<const DWORD*>(peBase + optOff + 108);
        dataDirOff = optOff + 112;
    } else {
        return false;
    }
    if (numDataDirs > 16) numDataDirs = 16;

    // Export directory is data dir index 0
    if (numDataDirs < 1) return false;
    DWORD exportRVA  = *reinterpret_cast<const DWORD*>(peBase + dataDirOff);
    DWORD exportSize = *reinterpret_cast<const DWORD*>(peBase + dataDirOff + 4);
    if (exportRVA == 0 || exportSize == 0) {
        LogDebug(L"[BunVFS/Export] No export directory (RVA=0x%lX, size=0x%lX)", exportRVA, exportSize);
        return false;
    }

    DWORD exportFileOff = RvaToFileOffset(peBase, peSize, exportRVA);
    if (exportFileOff == 0 || exportFileOff + 40 > peSize) {
        LogDebug(L"[BunVFS/Export] Export directory RVA 0x%lX -> file offset 0x%lX (invalid or out of bounds)",
                 exportRVA, exportFileOff);
        return false;
    }

    // IMAGE_EXPORT_DIRECTORY structure (40 bytes)
    // Offset 24: NumberOfNames (DWORD)
    // Offset 32: AddressOfNames (DWORD RVA -> array of RVAs to name strings)
    DWORD numberOfNames  = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 24);
    DWORD namesRVA       = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 32);

    // Also read DLL name from export dir
    DWORD dllNameRVA = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 12);
    if (dllNameRVA > 0) {
        DWORD dllNameOff = RvaToFileOffset(peBase, peSize, dllNameRVA);
        if (dllNameOff > 0 && dllNameOff + 1 < peSize) {
            const char* dn = reinterpret_cast<const char*>(peBase + dllNameOff);
            size_t maxLen = peSize - dllNameOff;
            size_t len = strnlen(dn, maxLen > 260 ? 260 : maxLen);
            LogDebug(L"[BunVFS/Export] Export DLL name: '%.260S'", dn);
        }
    }

    LogDebug(L"[BunVFS/Export] Export directory: RVA=0x%lX, fileOff=0x%lX, numberOfNames=%lu, namesRVA=0x%lX",
             exportRVA, exportFileOff, numberOfNames, namesRVA);

    if (outExportCount) *outExportCount = static_cast<int>(numberOfNames);

    if (numberOfNames == 0 || namesRVA == 0) return false;
    if (numberOfNames > 100000) {
        LogWarn(L"[BunVFS/Export] Suspicious export count: %lu", numberOfNames);
        return false;
    }

    DWORD namesFileOff = RvaToFileOffset(peBase, peSize, namesRVA);
    if (namesFileOff == 0 || namesFileOff + numberOfNames * 4 > peSize) {
        LogDebug(L"[BunVFS/Export] Names array out of bounds: fileOff=0x%lX", namesFileOff);
        return false;
    }

    size_t symbolLen = strlen(symbolName);
    bool found = false;
    int printedCount = 0;

    for (DWORD i = 0; i < numberOfNames; ++i) {
        DWORD nameRVA = *reinterpret_cast<const DWORD*>(peBase + namesFileOff + i * 4);
        DWORD nameOff = RvaToFileOffset(peBase, peSize, nameRVA);
        if (nameOff == 0 || nameOff >= peSize) continue;

        const char* name = reinterpret_cast<const char*>(peBase + nameOff);
        size_t maxLen = peSize - nameOff;
        size_t len = strnlen(name, maxLen > 512 ? 512 : maxLen);

        // Log first 20 exports and any match
        if (printedCount < 20) {
            LogDebug(L"[BunVFS/Export]   [%lu] '%.260S'", i, name);
            ++printedCount;
        } else if (printedCount == 20) {
            LogDebug(L"[BunVFS/Export]   ... (%lu more exports not shown)", numberOfNames - 20);
            ++printedCount;
        }

        if (len == symbolLen && memcmp(name, symbolName, symbolLen) == 0) {
            LogInfo(L"[BunVFS/Export] *** Found target symbol '%S' at export index %lu ***", symbolName, i);
            found = true;
            // Don't break - continue logging to show full picture
        }
    }

    if (!found) {
        LogWarn(L"[BunVFS/Export] Symbol '%S' NOT found among %lu exports.", symbolName, numberOfNames);
    }
    return found;
}

// Thoroughly validate an embedded PE DLL and compute its COMPLETE file size.
// This accounts for:
//   1) PE headers (SizeOfHeaders)
//   2) All section raw data (PointerToRawData + SizeOfRawData)
//   3) Certificate/Authenticode data (IMAGE_DIRECTORY_ENTRY_SECURITY, index 4)
//   4) Debug directory raw data (index 6)
//   5) FileAlignment alignment
// Returns 0 if the region is not a valid PE DLL.
static size_t ValidatePEDllAndGetCompleteSize(const BYTE* base, size_t maxLen) {
    if (maxLen < 0x200) {
        return 0;
    }
    if (base[0] != 'M' || base[1] != 'Z') return 0;

    DWORD peOff = *reinterpret_cast<const DWORD*>(base + 0x3C);
    if (peOff < 0x40 || peOff > 0x10000) return 0;
    if (peOff + 4 + 20 > maxLen) return 0;

    if (base[peOff] != 'P' || base[peOff + 1] != 'E' ||
        base[peOff + 2] != 0 || base[peOff + 3] != 0) return 0;

    size_t coffOff = peOff + 4;
    WORD machine        = *reinterpret_cast<const WORD*>(base + coffOff + 0);
    WORD numSections    = *reinterpret_cast<const WORD*>(base + coffOff + 2);
    WORD optHeaderSize  = *reinterpret_cast<const WORD*>(base + coffOff + 16);
    WORD characteristics = *reinterpret_cast<const WORD*>(base + coffOff + 18);

    LogDebug(L"[BunVFS/PE] COFF header: machine=0x%04X, sections=%u, optHdrSize=%u, chars=0x%04X",
             machine, numSections, optHeaderSize, characteristics);

    if (!(characteristics & 0x2000)) return 0;  // IMAGE_FILE_DLL
    if (machine != 0x014C && machine != 0x8664) return 0;
    if (numSections == 0 || numSections > 96) return 0;
    if (optHeaderSize < 96) return 0;

    size_t optOff = coffOff + 20;
    if (optOff + optHeaderSize > maxLen) return 0;

    WORD optMagic = *reinterpret_cast<const WORD*>(base + optOff);
    bool isPE32Plus = (optMagic == 0x020B);
    bool isPE32     = (optMagic == 0x010B);
    if (!isPE32 && !isPE32Plus) return 0;

    LogDebug(L"[BunVFS/PE] Format: %ls", isPE32Plus ? L"PE32+ (64-bit)" : L"PE32 (32-bit)");

    if (isPE32Plus && machine != 0x8664) return 0;
    if (isPE32 && machine != 0x014C) return 0;

    DWORD sizeOfHeaders = *reinterpret_cast<const DWORD*>(base + optOff + 60);
    DWORD fileAlignment = *reinterpret_cast<const DWORD*>(base + optOff + 36);
    if (fileAlignment == 0 || (fileAlignment & (fileAlignment - 1)) != 0) return 0;
    if (fileAlignment < 512 || fileAlignment > 65536) return 0;

    // SizeOfImage from optional header (useful for sanity checks)
    DWORD sizeOfImage = 0;
    if (isPE32) {
        sizeOfImage = *reinterpret_cast<const DWORD*>(base + optOff + 56);
    } else {
        sizeOfImage = *reinterpret_cast<const DWORD*>(base + optOff + 56);
    }

    LogDebug(L"[BunVFS/PE] SizeOfHeaders=0x%lX, FileAlignment=0x%lX, SizeOfImage=0x%lX",
             sizeOfHeaders, fileAlignment, sizeOfImage);

    DWORD numDataDirs = 0;
    size_t dataDirOff = 0;
    if (isPE32) {
        if (optHeaderSize < 96) return 0;
        numDataDirs = *reinterpret_cast<const DWORD*>(base + optOff + 92);
        dataDirOff = optOff + 96;
    } else {
        if (optHeaderSize < 112) return 0;
        numDataDirs = *reinterpret_cast<const DWORD*>(base + optOff + 108);
        dataDirOff = optOff + 112;
    }
    if (numDataDirs > 16) numDataDirs = 16;

    LogDebug(L"[BunVFS/PE] NumberOfRvaAndSizes=%lu", numDataDirs);

    size_t sectionTableOff = optOff + optHeaderSize;
    if (sectionTableOff + numSections * 40 > maxLen) return 0;

    // === Compute complete file size ===
    size_t totalSize = sizeOfHeaders;

    // 1) End of all section raw data
    for (WORD s = 0; s < numSections; ++s) {
        size_t shOff = sectionTableOff + s * 40;
        char secName[9] = {};
        memcpy(secName, base + shOff, 8);
        DWORD rawSize = *reinterpret_cast<const DWORD*>(base + shOff + 16);
        DWORD rawPtr  = *reinterpret_cast<const DWORD*>(base + shOff + 20);

        LogDebug(L"[BunVFS/PE]   Section[%u] '%.8S': RawSize=0x%lX, RawPtr=0x%lX",
                 s, secName, rawSize, rawPtr);

        if (rawSize > 0 && rawPtr > 0) {
            size_t end = static_cast<size_t>(rawPtr) + rawSize;
            if (end > maxLen) return 0;
            if (end > totalSize) totalSize = end;
        }
    }

    LogDebug(L"[BunVFS/PE] Size after sections: 0x%llX", (unsigned long long)totalSize);

    // 2) Certificate / Authenticode table (index 4) - uses FILE OFFSET, not RVA
    if (numDataDirs > 4) {
        size_t certEntryOff = dataDirOff + 4 * 8;
        if (certEntryOff + 8 <= optOff + optHeaderSize) {
            DWORD certFileOffset = *reinterpret_cast<const DWORD*>(base + certEntryOff);
            DWORD certSize       = *reinterpret_cast<const DWORD*>(base + certEntryOff + 4);
            if (certFileOffset > 0 && certSize > 0) {
                size_t certEnd = static_cast<size_t>(certFileOffset) + certSize;
                if (certEnd > maxLen) return 0;
                if (certEnd > totalSize) totalSize = certEnd;
                LogInfo(L"[BunVFS/PE] Certificate data: offset=0x%lX, size=0x%lX, end=0x%llX",
                        certFileOffset, certSize, (unsigned long long)certEnd);
            }
        }
    }

    // 3) Debug directory (index 6) - entries may have PointerToRawData outside sections
    if (numDataDirs > 6) {
        size_t dbgEntryOff = dataDirOff + 6 * 8;
        if (dbgEntryOff + 8 <= optOff + optHeaderSize) {
            DWORD dbgRVA  = *reinterpret_cast<const DWORD*>(base + dbgEntryOff);
            DWORD dbgSize = *reinterpret_cast<const DWORD*>(base + dbgEntryOff + 4);
            if (dbgRVA > 0 && dbgSize > 0) {
                DWORD dbgFileOff = RvaToFileOffset(base, maxLen, dbgRVA);
                if (dbgFileOff > 0) {
                    // Each IMAGE_DEBUG_DIRECTORY is 28 bytes
                    DWORD numEntries = dbgSize / 28;
                    LogDebug(L"[BunVFS/PE] Debug directory: RVA=0x%lX, fileOff=0x%lX, entries=%lu",
                             dbgRVA, dbgFileOff, numEntries);
                    for (DWORD d = 0; d < numEntries && dbgFileOff + d * 28 + 28 <= maxLen; ++d) {
                        size_t entOff = dbgFileOff + d * 28;
                        DWORD dbgDataSize = *reinterpret_cast<const DWORD*>(base + entOff + 16);
                        DWORD dbgDataPtr  = *reinterpret_cast<const DWORD*>(base + entOff + 24);
                        if (dbgDataSize > 0 && dbgDataPtr > 0) {
                            size_t dbgEnd = static_cast<size_t>(dbgDataPtr) + dbgDataSize;
                            if (dbgEnd <= maxLen && dbgEnd > totalSize) {
                                LogDebug(L"[BunVFS/PE]   Debug entry[%lu]: rawPtr=0x%lX, size=0x%lX, extends total to 0x%llX",
                                         d, dbgDataPtr, dbgDataSize, (unsigned long long)dbgEnd);
                                totalSize = dbgEnd;
                            }
                        }
                    }
                }
            }
        }
    }

    LogDebug(L"[BunVFS/PE] Size after cert+debug: 0x%llX", (unsigned long long)totalSize);

    // 4) Align total size up to FileAlignment
    size_t unalignedSize = totalSize;
    if (fileAlignment > 1) {
        totalSize = (totalSize + fileAlignment - 1) & ~(static_cast<size_t>(fileAlignment) - 1);
        if (totalSize > maxLen) totalSize = maxLen;
    }

    if (totalSize != unalignedSize) {
        LogDebug(L"[BunVFS/PE] Size after alignment to 0x%lX: 0x%llX (was 0x%llX)",
                 fileAlignment, (unsigned long long)totalSize, (unsigned long long)unalignedSize);
    }

    if (totalSize < 4096) return 0;

    LogInfo(L"[BunVFS/PE] Validated DLL: %ls, %u sections, computed size=%llu bytes (0x%llX)",
            isPE32Plus ? L"PE32+(x64)" : L"PE32(x86)",
            numSections, (unsigned long long)totalSize, (unsigned long long)totalSize);

    return totalSize;
}

// After extraction, verify the DLL is loadable by checking key PE structures
// and also verifying that expected exports (like "setLogCallback") exist.
static bool VerifyExtractedDll(const std::wstring& dllPath, bool checkExports = true) {
    LogInfo(L"[BunVFS/Verify] Verifying extracted DLL: %ls", dllPath.c_str());

    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogError(L"[BunVFS/Verify] Cannot open DLL file: %ls (err=%lu)", dllPath.c_str(), GetLastError());
        return false;
    }

    LARGE_INTEGER li{};
    GetFileSizeEx(hFile, &li);
    size_t fileSize = static_cast<size_t>(li.QuadPart);

    LogDebug(L"[BunVFS/Verify] File size: %llu bytes (0x%llX)",
             (unsigned long long)fileSize, (unsigned long long)fileSize);

    if (fileSize < 4096) {
        CloseHandle(hFile);
        LogWarn(L"[BunVFS/Verify] DLL too small: %llu bytes (minimum 4096)", (unsigned long long)fileSize);
        return false;
    }

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        LogError(L"[BunVFS/Verify] CreateFileMappingW failed: err=%lu", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    const BYTE* base = static_cast<const BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!base) {
        LogError(L"[BunVFS/Verify] MapViewOfFile failed: err=%lu", GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    bool valid = true;

    // 1) MZ + PE signature
    if (base[0] != 'M' || base[1] != 'Z') {
        LogError(L"[BunVFS/Verify] FAIL: Missing MZ signature (got 0x%02X 0x%02X)", base[0], base[1]);
        valid = false;
        goto done;
    }
    LogDebug(L"[BunVFS/Verify] PASS: MZ signature present");

    {
        DWORD peOff = *reinterpret_cast<const DWORD*>(base + 0x3C);
        if (peOff + 4 > fileSize) {
            LogError(L"[BunVFS/Verify] FAIL: e_lfanew=0x%lX exceeds file size", peOff);
            valid = false;
            goto done;
        }
        if (base[peOff] != 'P' || base[peOff + 1] != 'E') {
            LogError(L"[BunVFS/Verify] FAIL: No PE signature at offset 0x%lX", peOff);
            valid = false;
            goto done;
        }
        LogDebug(L"[BunVFS/Verify] PASS: PE signature at offset 0x%lX", peOff);

        // 2) DLL flag
        WORD chars = *reinterpret_cast<const WORD*>(base + peOff + 4 + 18);
        if (!(chars & 0x2000)) {
            LogError(L"[BunVFS/Verify] FAIL: IMAGE_FILE_DLL flag not set (chars=0x%04X)", chars);
            valid = false;
            goto done;
        }
        LogDebug(L"[BunVFS/Verify] PASS: DLL flag set (chars=0x%04X)", chars);

        // 3) All sections' raw data must be within file bounds
        WORD numSections = *reinterpret_cast<const WORD*>(base + peOff + 4 + 2);
        WORD optSize = *reinterpret_cast<const WORD*>(base + peOff + 4 + 16);
        size_t secOff = peOff + 4 + 20 + optSize;

        LogDebug(L"[BunVFS/Verify] Checking %u sections for file bounds...", numSections);

        for (WORD s = 0; s < numSections && secOff + s * 40 + 40 <= fileSize; ++s) {
            size_t sh = secOff + s * 40;
            char secName[9] = {};
            memcpy(secName, base + sh, 8);
            DWORD rawSize = *reinterpret_cast<const DWORD*>(base + sh + 16);
            DWORD rawPtr  = *reinterpret_cast<const DWORD*>(base + sh + 20);
            if (rawSize > 0 && rawPtr > 0) {
                size_t end = static_cast<size_t>(rawPtr) + rawSize;
                if (end > fileSize) {
                    LogError(L"[BunVFS/Verify] FAIL: Section[%u] '%.8S' extends beyond file: "
                             L"RawPtr=0x%lX + RawSize=0x%lX = 0x%llX > fileSize=0x%llX",
                             s, secName, rawPtr, rawSize, (unsigned long long)end, (unsigned long long)fileSize);
                    valid = false;
                    goto done;
                }
                LogDebug(L"[BunVFS/Verify]   Section[%u] '%.8S': OK (end=0x%llX)", s, secName, (unsigned long long)end);
            }
        }
        LogDebug(L"[BunVFS/Verify] PASS: All sections within file bounds");

        // 4) Check export directory and verify expected symbols
        if (checkExports) {
            int exportCount = 0;
            bool hasSetLogCallback = PEDllExportsSymbol(base, fileSize, "setLogCallback", &exportCount);

            if (exportCount == 0) {
                LogWarn(L"[BunVFS/Verify] WARNING: DLL has NO exports at all - likely wrong PE or truncated!");
                valid = false;
                goto done;
            }

            LogInfo(L"[BunVFS/Verify] DLL has %d exports, setLogCallback=%ls",
                    exportCount, hasSetLogCallback ? L"FOUND" : L"NOT FOUND");

            if (!hasSetLogCallback) {
                LogError(L"[BunVFS/Verify] FAIL: Required symbol 'setLogCallback' not found in exports.");
                LogError(L"[BunVFS/Verify]   This PE DLL is likely the wrong embedded image.");
                valid = false;
                goto done;
            }
            LogInfo(L"[BunVFS/Verify] PASS: Required export 'setLogCallback' present");
        }

        // 5) Check certificate data bounds
        size_t optOff2 = peOff + 4 + 20;
        WORD magic = *reinterpret_cast<const WORD*>(base + optOff2);
        DWORD numDD = 0;
        size_t ddOff = 0;
        if (magic == 0x010B) { numDD = *reinterpret_cast<const DWORD*>(base + optOff2 + 92); ddOff = optOff2 + 96; }
        else if (magic == 0x020B) { numDD = *reinterpret_cast<const DWORD*>(base + optOff2 + 108); ddOff = optOff2 + 112; }
        if (numDD > 16) numDD = 16;

        if (numDD > 4 && ddOff + 4 * 8 + 8 <= fileSize) {
            DWORD certOff  = *reinterpret_cast<const DWORD*>(base + ddOff + 4 * 8);
            DWORD certSize = *reinterpret_cast<const DWORD*>(base + ddOff + 4 * 8 + 4);
            if (certOff > 0 && certSize > 0) {
                size_t certEnd = static_cast<size_t>(certOff) + certSize;
                if (certEnd > fileSize) {
                    LogError(L"[BunVFS/Verify] FAIL: Certificate data extends beyond file");
                    valid = false;
                    goto done;
                }
                LogDebug(L"[BunVFS/Verify] Certificate: offset=0x%lX, size=0x%lX", certOff, certSize);
            }
        }
    }

done:
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);

    if (valid) {
        LogInfo(L"[BunVFS/Verify] ===== DLL VERIFICATION PASSED ===== %ls (%llu bytes)",
                dllPath.c_str(), (unsigned long long)fileSize);
    } else {
        LogError(L"[BunVFS/Verify] ===== DLL VERIFICATION FAILED ===== %ls", dllPath.c_str());
    }
    return valid;
}

// Candidate PE DLL found during scan
struct PECandidate {
    size_t offset;
    size_t size;
    bool hasTargetExport;
    int exportCount;
};

// Extract embedded DLL from a Bun standalone exe into outDir.
// Uses ValidatePEDllAndGetCompleteSize for sizing, then verifies exports.
// Scans ALL candidates and picks the one that exports "setLogCallback".
static bool ExtractEmbeddedDllFromExe(const std::wstring& exePath,
                                       const std::wstring& outDir,
                                       const std::wstring& dllName,
                                       std::wstring& outPath) {
    LogInfo(L"[BunVFS/Extract] Starting DLL extraction from: %ls", exePath.c_str());
    LogInfo(L"[BunVFS/Extract] Output directory: %ls", outDir.c_str());
    LogInfo(L"[BunVFS/Extract] Expected DLL name: %ls", dllName.empty() ? L"(auto-detect)" : dllName.c_str());

    HANDLE hFile = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogError(L"[BunVFS/Extract] Cannot open exe: %ls (err=%lu)", exePath.c_str(), GetLastError());
        return false;
    }

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(hFile, &li) || li.QuadPart < 4096) {
        LogError(L"[BunVFS/Extract] File too small or GetFileSizeEx failed: size=%lld", li.QuadPart);
        CloseHandle(hFile);
        return false;
    }
    size_t fileSize = static_cast<size_t>(li.QuadPart);
    LogInfo(L"[BunVFS/Extract] Exe file size: %llu bytes (%.2f MB)",
            (unsigned long long)fileSize, (double)fileSize / (1024.0 * 1024.0));

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        LogError(L"[BunVFS/Extract] CreateFileMappingW failed: err=%lu", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    const BYTE* base = static_cast<const BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!base) {
        LogError(L"[BunVFS/Extract] MapViewOfFile failed: err=%lu", GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    // Phase 1: Scan for ALL valid PE DLL candidates
    std::vector<PECandidate> candidates;
    int mzCandidates = 0;

    size_t scanStart = 0x10000;  // 64KB - skip past main exe PE header area
    if (scanStart >= fileSize) scanStart = 4096;

    LogInfo(L"[BunVFS/Extract] Phase 1: Scanning for ALL embedded PE DLL candidates...");
    LogInfo(L"[BunVFS/Extract]   Scan range: 0x%llX to 0x%llX",
            (unsigned long long)scanStart, (unsigned long long)fileSize);

    DWORD scanStartTick = GetTickCount();

    for (size_t off = scanStart; off + 0x200 < fileSize; ++off) {
        if (base[off] != 'M' || base[off + 1] != 'Z') continue;

        ++mzCandidates;
        if (mzCandidates <= 10 || mzCandidates % 50 == 0) {
            LogDebug(L"[BunVFS/Extract] MZ candidate #%d at offset 0x%llX (%.1f%%)",
                     mzCandidates, (unsigned long long)off,
                     100.0 * (double)off / (double)fileSize);
        }

        size_t remaining = fileSize - off;
        size_t peSize = ValidatePEDllAndGetCompleteSize(base + off, remaining);
        if (peSize == 0) continue;

        // Check if this candidate exports "setLogCallback"
        int exportCount = 0;
        bool hasExport = PEDllExportsSymbol(base + off, peSize, "setLogCallback", &exportCount);

        PECandidate cand;
        cand.offset = off;
        cand.size = peSize;
        cand.hasTargetExport = hasExport;
        cand.exportCount = exportCount;
        candidates.push_back(cand);

        LogInfo(L"[BunVFS/Extract] Valid PE DLL #%llu at offset 0x%llX: size=%llu bytes, exports=%d, setLogCallback=%ls",
                (unsigned long long)candidates.size(), (unsigned long long)off,
                (unsigned long long)peSize, exportCount,
                hasExport ? L"YES" : L"NO");

        // Skip past this PE image to avoid finding sub-images
        if (peSize > 0x200) {
            off += peSize - 1;  // -1 because the for loop will ++off
        }
    }

    DWORD scanElapsed = GetTickCount() - scanStartTick;
    LogInfo(L"[BunVFS/Extract] Phase 1 complete in %lu ms: %d MZ candidates, %llu valid PE DLLs found",
            scanElapsed, mzCandidates, (unsigned long long)candidates.size());

    if (candidates.empty()) {
        LogWarn(L"[BunVFS/Extract] No valid PE DLL found in exe. DLL may be compressed/encrypted.");
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    // Phase 2: Select best candidate
    // Priority: candidates with "setLogCallback" export, then largest by export count
    LogInfo(L"[BunVFS/Extract] Phase 2: Selecting best candidate from %llu options...",
            (unsigned long long)candidates.size());

    const PECandidate* best = nullptr;
    for (const auto& c : candidates) {
        LogDebug(L"[BunVFS/Extract]   Candidate: offset=0x%llX, size=%llu, exports=%d, hasTarget=%ls",
                 (unsigned long long)c.offset, (unsigned long long)c.size,
                 c.exportCount, c.hasTargetExport ? L"YES" : L"NO");

        if (!best) {
            best = &c;
        } else if (c.hasTargetExport && !best->hasTargetExport) {
            // Prefer candidate with the target export
            best = &c;
        } else if (c.hasTargetExport == best->hasTargetExport) {
            // Among equal export match status, prefer more exports (richer DLL)
            if (c.exportCount > best->exportCount) {
                best = &c;
            }
        }
    }

    if (!best) {
        LogError(L"[BunVFS/Extract] No candidate selected (should not happen).");
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    LogInfo(L"[BunVFS/Extract] Selected candidate: offset=0x%llX, size=%llu bytes, exports=%d, hasTarget=%ls",
            (unsigned long long)best->offset, (unsigned long long)best->size,
            best->exportCount, best->hasTargetExport ? L"YES" : L"NO");

    if (!best->hasTargetExport) {
        LogWarn(L"[BunVFS/Extract] WARNING: No candidate has 'setLogCallback' export! "
                L"Extracting best available, but LoadLibrary/GetProcAddress may still fail.");
    }

    // Phase 3: Extract selected candidate to disk
    std::wstring name = dllName.empty() ? L"opentui.dll" : dllName;
    outPath = outDir;
    if (!outPath.empty() && outPath.back() != L'\\') outPath += L'\\';
    outPath += name;

    LogInfo(L"[BunVFS/Extract] Phase 3: Extracting to %ls...", outPath.c_str());

    bool found = false;
    HANDLE hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut != INVALID_HANDLE_VALUE) {
        size_t written_total = 0;
        const size_t chunkSize = 4 * 1024 * 1024;
        bool writeOk = true;

        while (written_total < best->size) {
            DWORD toWrite = static_cast<DWORD>(
                min(chunkSize, best->size - written_total));
            DWORD written = 0;
            if (!WriteFile(hOut, base + best->offset + written_total, toWrite, &written, nullptr) ||
                written != toWrite) {
                LogError(L"[BunVFS/Extract] Write failed at byte %llu: err=%lu",
                         (unsigned long long)written_total, GetLastError());
                CloseHandle(hOut);
                DeleteFileW(outPath.c_str());
                writeOk = false;
                break;
            }
            written_total += written;
        }

        if (writeOk) {
            CloseHandle(hOut);
            LogInfo(L"[BunVFS/Extract] Wrote %llu bytes to %ls",
                    (unsigned long long)written_total, outPath.c_str());

            // Final verification on the extracted file
            LogInfo(L"[BunVFS/Extract] Running post-extraction verification...");
            if (VerifyExtractedDll(outPath, true)) {
                found = true;
                LogInfo(L"[BunVFS/Extract] Extraction and verification SUCCESSFUL.");
            } else {
                LogError(L"[BunVFS/Extract] Post-extraction verification FAILED!");
                // Try with expanded size: maybe we need more data from the file
                // Attempt extracting with remaining-to-end-of-file as size
                size_t remainingSize = fileSize - best->offset;
                if (remainingSize > best->size && remainingSize < best->size * 3) {
                    LogWarn(L"[BunVFS/Extract] Retrying with expanded size: %llu -> %llu (remaining to EOF)",
                            (unsigned long long)best->size, (unsigned long long)remainingSize);
                    hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0,
                                      nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hOut != INVALID_HANDLE_VALUE) {
                        written_total = 0;
                        writeOk = true;
                        while (written_total < remainingSize) {
                            DWORD toW = static_cast<DWORD>(min(chunkSize, remainingSize - written_total));
                            DWORD w = 0;
                            if (!WriteFile(hOut, base + best->offset + written_total, toW, &w, nullptr) || w != toW) {
                                writeOk = false;
                                break;
                            }
                            written_total += w;
                        }
                        CloseHandle(hOut);
                        if (writeOk && VerifyExtractedDll(outPath, true)) {
                            found = true;
                            LogInfo(L"[BunVFS/Extract] Expanded extraction SUCCEEDED: %llu bytes.", (unsigned long long)remainingSize);
                        } else {
                            LogError(L"[BunVFS/Extract] Expanded extraction also FAILED. Deleting.");
                            DeleteFileW(outPath.c_str());
                        }
                    }
                } else {
                    DeleteFileW(outPath.c_str());
                }
            }
        }
    } else {
        LogError(L"[BunVFS/Extract] Failed to create output file: %ls (err=%lu)", outPath.c_str(), GetLastError());
    }

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);

    LogInfo(L"[BunVFS/Extract] Final result: %ls", found ? L"SUCCESS" : L"FAILED");
    return found;
}

// Resolve absolute path of the exe
static std::wstring ResolveExeFullPath(PCWSTR exeName) {
    if (!exeName) return L"";
    std::wstring image = ParseImagePathFromCommandLine(exeName);
    if (image.empty()) return L"";

    LogDebug(L"[BunVFS/Resolve] Resolving exe path for: %ls", image.c_str());

    if (image.find(L'\\') != std::wstring::npos || image.find(L'/') != std::wstring::npos) {
        DWORD attrs = GetFileAttributesW(image.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            LogDebug(L"[BunVFS/Resolve] Direct path exists: %ls", image.c_str());
            return image;
        }
        LogDebug(L"[BunVFS/Resolve] Direct path not found: %ls", image.c_str());
        return L"";
    }

    std::wstring exeDir = GetExeDir();
    if (!exeDir.empty()) {
        std::wstring c = JoinPath(exeDir, image);
        DWORD a = GetFileAttributesW(c.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            LogDebug(L"[BunVFS/Resolve] Found in exe directory: %ls", c.c_str());
            return c;
        }
    }

    for (const auto& p : AllowedPaths) {
        std::wstring c = JoinPath(p, image);
        DWORD a = GetFileAttributesW(c.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            LogDebug(L"[BunVFS/Resolve] Found in allowed path: %ls", c.c_str());
            return c;
        }
    }

    wchar_t fullPath[MAX_PATH * 2] = {};
    DWORD n = SearchPathW(nullptr, image.c_str(), L".exe", _countof(fullPath), fullPath, nullptr);
    if (n > 0 && n < _countof(fullPath)) {
        LogDebug(L"[BunVFS/Resolve] Found via SearchPathW: %ls", fullPath);
        return std::wstring(fullPath, n);
    }

    LogWarn(L"[BunVFS/Resolve] Could not resolve exe path for: %ls", image.c_str());
    return L"";
}

// Create B:\~BUN\root\ on disk, extract embedded DLL, and map B: drive
static bool PrepareBunVirtualDrive(PSID appContainerSid) {
    if (!ExeToLaunch) {
        LogDebug(L"[BunVFS] No exe to launch, skipping virtual drive setup.");
        return false;
    }

    std::wstring image = ParseImagePathFromCommandLine(ExeToLaunch);
    std::wstring nameLower = ToLowerCopy(GetFileNamePart(image));

    LogDebug(L"[BunVFS] Checking if exe needs Bun virtual drive: name='%ls'", nameLower.c_str());

    if (nameLower.find(L"opencode") == std::wstring::npos) {
        LogDebug(L"[BunVFS] Not an OpenCode executable, skipping virtual drive.");
        return false;
    }

    LogInfo(L"[BunVFS] ====== Starting Bun Virtual Drive Setup ======");

    // Check if B: is already in use (e.g. a real fixed drive on the system).
    // If so, we CANNOT map our staging dir to B:, but we MUST still extract
    // the DLL and set up fallback paths (PATH prepend)
    // so the child process can find the opentui DLL.
    UINT driveType = GetDriveTypeW(L"B:\\");
    LogDebug(L"[BunVFS] B: drive type: %u", driveType);
    bool bDriveAvailable = (driveType == DRIVE_NO_ROOT_DIR || driveType == 0);
    if (!bDriveAvailable) {
        LogWarn(L"[BunVFS] B: drive already exists (type=%u). Will skip B: mapping but still extract DLL for fallback paths.", driveType);
    }

    std::wstring exeFullPath = ResolveExeFullPath(ExeToLaunch);
    if (exeFullPath.empty()) {
        LogWarn(L"[BunVFS] Cannot locate exe file for DLL extraction.");
        return false;
    }

    LogInfo(L"[BunVFS] Resolved exe path: %ls", exeFullPath.c_str());

    // Get exe file info
    {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(exeFullPath.c_str(), GetFileExInfoStandard, &fad)) {
            ULARGE_INTEGER sz;
            sz.HighPart = fad.nFileSizeHigh;
            sz.LowPart = fad.nFileSizeLow;
            FILETIME ft = fad.ftLastWriteTime;
            SYSTEMTIME st{};
            FileTimeToSystemTime(&ft, &st);
            LogInfo(L"[BunVFS] Exe info: size=%llu bytes (%.2f MB), modified=%04u-%02u-%02u %02u:%02u:%02u",
                    sz.QuadPart, (double)sz.QuadPart / (1024.0 * 1024.0),
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }
    }

    std::wstring stagingBase = AllowedPaths.empty() ? GetExeDir() : AllowedPaths[0];
    if (stagingBase.empty()) {
        LogWarn(L"[BunVFS] No suitable base directory for staging.");
        return false;
    }

    g_BunStagingDir = JoinPath(stagingBase, L".bun-vfs");
    std::wstring bunDir = JoinPath(g_BunStagingDir, L"~BUN");
    std::wstring dllDir = JoinPath(bunDir, L"root");

    LogInfo(L"[BunVFS] Staging layout: %ls -> ~BUN -> root", g_BunStagingDir.c_str());

    CreateDirectoryW(g_BunStagingDir.c_str(), nullptr);
    CreateDirectoryW(bunDir.c_str(), nullptr);
    CreateDirectoryW(dllDir.c_str(), nullptr);

    if (!DirectoryExists(dllDir)) {
        LogError(L"[BunVFS] Failed to create DLL directory: %ls", dllDir.c_str());
        return false;
    }

    // Find expected DLL name from binary
    LogInfo(L"[BunVFS] Scanning exe for embedded DLL name...");
    std::wstring dllName;
    {
        HANDLE hF = CreateFileW(exeFullPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hF != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz{};
            GetFileSizeEx(hF, &sz);
            HANDLE hM = CreateFileMappingW(hF, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (hM) {
                const BYTE* d = static_cast<const BYTE*>(MapViewOfFile(hM, FILE_MAP_READ, 0, 0, 0));
                if (d) {
                    dllName = FindDllNameInBinary(d, static_cast<size_t>(sz.QuadPart));
                    UnmapViewOfFile(d);
                }
                CloseHandle(hM);
            }
            CloseHandle(hF);
        }
    }

    if (!dllName.empty()) {
        LogInfo(L"[BunVFS] Expected DLL name: %ls", dllName.c_str());
    } else {
        LogWarn(L"[BunVFS] Could not find DLL name pattern in exe.");
    }

    // Check if already extracted and still valid (including export check)
    bool alreadyExtracted = false;
    std::wstring dllPath;
    if (!dllName.empty()) {
        dllPath = JoinPath(dllDir, dllName);
        DWORD a = GetFileAttributesW(dllPath.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            LogInfo(L"[BunVFS] Found existing DLL: %ls", dllPath.c_str());
            LogInfo(L"[BunVFS] Re-verifying (including export check)...");
            if (VerifyExtractedDll(dllPath, true)) {
                LogInfo(L"[BunVFS] Existing DLL verified OK, reusing.");
                alreadyExtracted = true;
            } else {
                LogWarn(L"[BunVFS] Existing DLL FAILED verification! Deleting and re-extracting.");
                DeleteFileW(dllPath.c_str());
            }
        }
    }

    if (!alreadyExtracted) {
        LogInfo(L"[BunVFS] Starting DLL extraction (with export validation)...");
        std::wstring extractedPath;
        if (ExtractEmbeddedDllFromExe(exeFullPath, dllDir, dllName, extractedPath)) {
            dllPath = extractedPath;
            LogInfo(L"[BunVFS] DLL extraction successful: %ls", dllPath.c_str());
        } else {
            LogWarn(L"[BunVFS] Could not extract DLL. Mapping B: anyway for Bun's own attempt.");
        }
    }

    // === DLL Fallback Mechanism ===
    // Even if B: mapping works, AppContainer namespace isolation may make it
    // invisible to the child. Set up fallback paths that always work:

    // Fallback 1: Add DLL staging directory to PATH prepend
    // This allows LoadLibrary("opentui-xxx.dll") to find it via PATH search.
    if (!dllDir.empty() && DirectoryExists(dllDir)) {
        if (AddPathPrependUnique(dllDir)) {
            LogInfo(L"[BunVFS] Fallback 1: Added DLL directory to PATH prepend: %ls", dllDir.c_str());
        }
    }

    // Grant AppContainer full access
    if (appContainerSid) {
        LogInfo(L"[BunVFS] Granting AppContainer access to staging dir...");
        DWORD dw = GrantFullControlToSidOnPath(g_BunStagingDir.c_str(), appContainerSid);
        if (dw == ERROR_SUCCESS) {
            LogInfo(L"[BunVFS] Granted FILE_ALL_ACCESS on: %ls", g_BunStagingDir.c_str());
        } else {
            LogWarn(L"[BunVFS] Grant (F) failed: %ls (err=%lu)", g_BunStagingDir.c_str(), dw);
        }
    }

    // Map B: -> staging dir (only if B: is not already in use)
    if (bDriveAvailable) {
        LogInfo(L"[BunVFS] Mapping B: -> %ls", g_BunStagingDir.c_str());
        if (DefineDosDeviceW(0, L"B:", g_BunStagingDir.c_str())) {
            g_BunDriveMapped = true;
            g_BunDriveTarget = g_BunStagingDir;
            LogInfo(L"[BunVFS] DefineDosDeviceW succeeded.");
            LogWarn(L"[BunVFS] Note: B: mapping may not be visible inside AppContainer due to namespace isolation.");
        } else {
            DWORD err = GetLastError();
            LogWarn(L"[BunVFS] DefineDosDeviceW failed (err=%lu) - non-fatal, fallback paths available.", err);
        }
    } else {
        LogInfo(L"[BunVFS] Skipping B: mapping (drive already in use, type=%u).", driveType);
    }

    // Verify B: mapping if we created one
    if (g_BunDriveMapped) {
        if (DirectoryExists(L"B:\\~BUN\\root")) {
            LogInfo(L"[BunVFS] Verified: B:\\~BUN\\root is accessible.");
        } else {
            LogWarn(L"[BunVFS] B:\\~BUN\\root NOT accessible after mapping!");
        }
    }

    // List DLL dir contents
    {
        std::wstring searchPattern = dllDir + L"\\*";
        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            int fileCount = 0;
            do {
                if (IsDotOrDotDot(fd.cFileName)) continue;
                ULARGE_INTEGER sz;
                sz.HighPart = fd.nFileSizeHigh;
                sz.LowPart = fd.nFileSizeLow;
                LogInfo(L"[BunVFS]   File: %ls (%llu bytes)", fd.cFileName, sz.QuadPart);
                ++fileCount;
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
            LogInfo(L"[BunVFS] DLL directory: %d file(s).", fileCount);
        }
    }

    // Confirm kernel mapping (if we created one)
    if (g_BunDriveMapped) {
        wchar_t devTarget[4096] = {};
        DWORD n = QueryDosDeviceW(L"B:", devTarget, _countof(devTarget));
        if (n > 0) LogInfo(L"[BunVFS] QueryDosDeviceW('B:'): '%ls'", devTarget);
    }

    // Log fallback summary
    LogInfo(L"[BunVFS] DLL loading fallback mechanisms:");
    LogInfo(L"[BunVFS]   1. B: drive mapping: %ls",
            g_BunDriveMapped ? L"ACTIVE (may not be visible in AppContainer)" : L"NOT AVAILABLE");
    if (!dllDir.empty() && DirectoryExists(dllDir))
        LogInfo(L"[BunVFS]   2. DLL in PATH: %ls", dllDir.c_str());

    // === Fallback 2: Copy DLL to %LOCALAPPDATA%\.bun\~BUN\root\ ===
    // When B: drive is not visible inside AppContainer, Bun's runtime may
    // fall back to loading DLLs from %LOCALAPPDATA%\.bun\~BUN\root\.
    // We mirror the staging directory structure there.
    // Also try exeDir\.bun\~BUN\root\ in case Bun resolves the exe directory.
    if (!dllPath.empty()) {
        std::wstring dllFileName = GetFileNamePart(dllPath);
        std::wstring exeDir = GetExeDir();

        // Try multiple candidate base directories for .bun fallback
        std::wstring candidateBases[3];
        int numCandidates = 0;

        // Candidate 1: exeDir (where opencode.exe lives)
        if (!exeDir.empty()) candidateBases[numCandidates++] = exeDir;

        // Candidate 2: LOCALAPPDATA (from env overrides if set, otherwise from environment)
        {
            std::wstring localAppData;
            for (const auto& ov : EnvOverrides) {
                if (IEquals(ov.name, L"LOCALAPPDATA")) { localAppData = ov.value; break; }
            }
            if (localAppData.empty()) localAppData = GetEnvVarCopy(L"LOCALAPPDATA");
            if (!localAppData.empty() && !IEquals(localAppData, exeDir))
                candidateBases[numCandidates++] = localAppData;
        }

        // Candidate 3: AllowedPaths[0] (staging base, if different from above)
        if (!AllowedPaths.empty() && !AllowedPaths[0].empty()) {
            bool dup = false;
            for (int i = 0; i < numCandidates; ++i) {
                if (IEquals(AllowedPaths[0], candidateBases[i])) { dup = true; break; }
            }
            if (!dup) candidateBases[numCandidates++] = AllowedPaths[0];
        }

        LogInfo(L"[BunVFS] Fallback 2: Creating .bun mirror directories (%d candidates)...", numCandidates);

        for (int i = 0; i < numCandidates; ++i) {
            std::wstring bunFallbackBase = JoinPath(candidateBases[i], L".bun");
            std::wstring bunFallbackBun  = JoinPath(bunFallbackBase, L"~BUN");
            std::wstring bunFallbackRoot = JoinPath(bunFallbackBun, L"root");
            std::wstring bunFallbackDll  = JoinPath(bunFallbackRoot, dllFileName);

            CreateDirectoryW(bunFallbackBase.c_str(), nullptr);
            CreateDirectoryW(bunFallbackBun.c_str(), nullptr);
            CreateDirectoryW(bunFallbackRoot.c_str(), nullptr);

            if (DirectoryExists(bunFallbackRoot)) {
                // Copy DLL to fallback location (overwrite if exists)
                if (CopyFileW(dllPath.c_str(), bunFallbackDll.c_str(), FALSE)) {
                    LogInfo(L"[BunVFS]   Fallback 2[%d]: Copied DLL to %ls", i, bunFallbackDll.c_str());
                    g_BunFallbackDirs.push_back(bunFallbackBase);

                    // Add to PATH prepend
                    if (AddPathPrependUnique(bunFallbackRoot)) {
                        LogInfo(L"[BunVFS]   Fallback 2[%d]: Added to PATH: %ls", i, bunFallbackRoot.c_str());
                    }

                    // Grant AppContainer access to the .bun tree
                    if (appContainerSid) {
                        GrantFullControlToSidOnPath(bunFallbackBase.c_str(), appContainerSid);
                    }

                    // Add to allowed paths for ACL
                    AddAllowedPathUnique(bunFallbackBase);
                } else {
                    DWORD copyErr = GetLastError();
                    LogWarn(L"[BunVFS]   Fallback 2[%d]: CopyFile to %ls failed (err=%lu)", i, bunFallbackDll.c_str(), copyErr);
                }
            } else {
                LogWarn(L"[BunVFS]   Fallback 2[%d]: Could not create directory: %ls", i, bunFallbackRoot.c_str());
            }
        }

        LogInfo(L"[BunVFS]   3. .bun fallback directories: CONFIGURED");
    }

    LogInfo(L"[BunVFS] ====== Bun Virtual Drive Setup Complete ======");
    return true;
}

// Thread-safe cleanup: remove B: drive mapping
static void CleanupBunVirtualDrive() {
    if (InterlockedCompareExchange(&g_BunCleanupDone, 1, 0) != 0) {
        LogDebug(L"[BunVFS/Cleanup] Already cleaned up, skipping.");
        return;
    }

    // Step 1: Remove B: drive mapping (if active)
    if (g_BunDriveMapped) {
        LogInfo(L"[BunVFS/Cleanup] Removing B: -> %ls ...", g_BunDriveTarget.c_str());

        if (DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
                             L"B:", g_BunDriveTarget.c_str())) {
            LogInfo(L"[BunVFS/Cleanup] B: drive mapping removed.");
        } else {
            DWORD err = GetLastError();
            LogWarn(L"[BunVFS/Cleanup] Failed to remove B: mapping (err=%lu). May need: subst B: /d", err);
        }

        UINT driveType = GetDriveTypeW(L"B:\\");
        if (driveType == DRIVE_NO_ROOT_DIR || driveType == 0) {
            LogInfo(L"[BunVFS/Cleanup] Verified: B: drive removed (type=%u).", driveType);
        } else {
            LogWarn(L"[BunVFS/Cleanup] B: still exists (type=%u)!", driveType);
        }

        g_BunDriveMapped = false;
    } else {
        LogDebug(L"[BunVFS/Cleanup] No B: mapping to remove.");
    }

    // Step 2: Delete staging directory (.bun-vfs)
    if (!g_BunStagingDir.empty() && DirectoryExists(g_BunStagingDir)) {
        LogInfo(L"[BunVFS/Cleanup] Deleting staging directory: %ls", g_BunStagingDir.c_str());
        DWORD dw = DeleteTreeNoFollow(g_BunStagingDir);
        if (dw == ERROR_SUCCESS) {
            LogInfo(L"[BunVFS/Cleanup] Staging directory deleted successfully.");
        } else {
            LogWarn(L"[BunVFS/Cleanup] Failed to delete staging directory: %ls (err=%lu)", g_BunStagingDir.c_str(), dw);
        }
    }

    // Step 3: Delete .bun fallback directories
    for (const auto& fbDir : g_BunFallbackDirs) {
        if (!fbDir.empty() && DirectoryExists(fbDir)) {
            LogInfo(L"[BunVFS/Cleanup] Deleting .bun fallback: %ls", fbDir.c_str());
            DWORD dw = DeleteTreeNoFollow(fbDir);
            if (dw == ERROR_SUCCESS) {
                LogInfo(L"[BunVFS/Cleanup] Fallback directory deleted: %ls", fbDir.c_str());
            } else {
                LogWarn(L"[BunVFS/Cleanup] Failed to delete fallback: %ls (err=%lu)", fbDir.c_str(), dw);
            }
        }
    }
    g_BunFallbackDirs.clear();
}

static void AtExitCleanupBunDrive() {
    LogDebug(L"[BunVFS/Cleanup] atexit handler invoked.");
    CleanupBunVirtualDrive();
}

static LONG WINAPI BunDriveCrashHandler(EXCEPTION_POINTERS* ep) {
    if (ep && ep->ExceptionRecord) {
        LogError(L"[BunVFS/Cleanup] Unhandled exception: code=0x%08lX, addr=%p",
                 ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
    }
    CleanupBunVirtualDrive();
    return EXCEPTION_CONTINUE_SEARCH;
}

// ========================================================================
// Environment Block Builder
// ========================================================================
static bool BuildChildEnvBlockFromOverrides() {
    if (EnvOverrides.empty() && PathPrependEntries.empty()) {
        LogDebug(L"[Env] No overrides or PATH prepends, skipping env block build.");
        return false;
    }

    LogInfo(L"[Env] Building child environment block: %llu overrides, %llu PATH prepends",
            (unsigned long long)EnvOverrides.size(), (unsigned long long)PathPrependEntries.size());

    LPWCH env = GetEnvironmentStringsW();
    std::vector<std::wstring> rawSpecial;
    std::vector<EnvKV> vars;

    if (env) {
        int totalVars = 0;
        for (LPWCH p = env; *p;) {
            size_t len = wcslen(p);
            std::wstring entry(p, p + len);
            if (!entry.empty() && entry[0] == L'=') rawSpecial.push_back(entry);
            else {
                size_t eq = entry.find(L'=');
                if (eq != std::wstring::npos && eq > 0)
                    vars.push_back(EnvKV{ entry.substr(0, eq), entry.substr(eq + 1) });
            }
            ++totalVars;
            p += len + 1;
        }
        FreeEnvironmentStringsW(env);
        LogDebug(L"[Env] Inherited %d vars from parent (%llu special, %llu normal)",
                 totalVars, (unsigned long long)rawSpecial.size(), (unsigned long long)vars.size());
    }

    for (const auto& ov : EnvOverrides) {
        if (ov.name.empty() || ov.name.find(L'=') != std::wstring::npos) continue;
        bool replaced = false;
        for (auto& cur : vars) {
            if (IEquals(cur.name, ov.name)) {
                LogDebug(L"[Env] Override: %ls = '%ls' (was: '%ls')", ov.name.c_str(), ov.value.c_str(), cur.value.c_str());
                cur.value = ov.value;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            LogDebug(L"[Env] New var: %ls = '%ls'", ov.name.c_str(), ov.value.c_str());
            vars.push_back(ov);
        }
    }

    if (!PathPrependEntries.empty()) {
        std::wstring prependJoined;
        for (const auto& p : PathPrependEntries) {
            if (p.empty()) continue;
            if (!prependJoined.empty()) prependJoined.push_back(L';');
            prependJoined.append(p);
        }
        if (!prependJoined.empty()) {
            auto it = std::find_if(vars.begin(), vars.end(),
                                   [](const EnvKV& kv) { return _wcsicmp(kv.name.c_str(), L"PATH") == 0; });
            if (it == vars.end()) {
                vars.push_back(EnvKV{ L"PATH", prependJoined });
                LogDebug(L"[Env] Created new PATH: %ls", prependJoined.c_str());
            } else if (it->value.empty()) {
                it->value = prependJoined;
                LogDebug(L"[Env] Set empty PATH to: %ls", prependJoined.c_str());
            } else {
                it->value = prependJoined + L";" + it->value;
                LogDebug(L"[Env] Prepended to PATH: %ls", prependJoined.c_str());
            }
        }
    }

    std::sort(vars.begin(), vars.end(), [](const EnvKV& a, const EnvKV& b) {
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });

    g_ChildEnv.clear();
    for (const auto& e : rawSpecial) {
        g_ChildEnv.insert(g_ChildEnv.end(), e.begin(), e.end());
        g_ChildEnv.push_back(L'\0');
    }
    for (const auto& e : vars) {
        std::wstring line = e.name + L"=" + e.value;
        g_ChildEnv.insert(g_ChildEnv.end(), line.begin(), line.end());
        g_ChildEnv.push_back(L'\0');
    }
    g_ChildEnv.push_back(L'\0');

    LogInfo(L"[Env] Child env block ready: %llu vars, %llu wchars total",
            (unsigned long long)vars.size(), (unsigned long long)g_ChildEnv.size());
    return true;
}

// ========================================================================
// Process Launcher (AppContainer mode)
// ========================================================================
static DWORD LaunchProcess(PSID packageSid) {
    DWORD result = ERROR_SUCCESS;

    LogInfo(L"[Launch] Preparing to launch child process...");
    LogInfo(L"[Launch]   Command: %ls", ExeToLaunch);
    LogInfo(L"[Launch]   Wait: %ls, LPAC: %ls, NoWin32k: %ls, NewConsole: %ls",
            WaitForExit ? L"yes" : L"no", LaunchAsLpac ? L"yes" : L"no",
            NoWin32k ? L"yes" : L"no", UseNewConsole ? L"yes" : L"no");

    bool useConPty = false;
    void* hPC = nullptr;
    HANDLE hPipeIn_R  = nullptr, hPipeIn_W  = nullptr;
    HANDLE hPipeOut_R = nullptr, hPipeOut_W = nullptr;
    HANDLE hRelayIn = nullptr, hRelayOut = nullptr, hStopEvent = nullptr;
    InputRelayCtx inputCtx{};
    DWORD savedInputMode = 0, savedOutputMode = 0;
    bool inputModeChanged = false, outputModeChanged = false;

    if (WaitForExit && !UseNewConsole && UseConPty && InitConPtyApi()) {
        LogInfo(L"[Launch] Setting up ConPTY pseudoconsole...");
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        BOOL pipeOk = CreatePipe(&hPipeIn_R, &hPipeIn_W, &sa, 0) &&
                      CreatePipe(&hPipeOut_R, &hPipeOut_W, &sa, 0);
        if (pipeOk) {
            SetHandleInformation(hPipeIn_W,  HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(hPipeOut_R, HANDLE_FLAG_INHERIT, 0);
            COORD conSize = GetCurrentConsoleSize();
            HRESULT hr = g_pfnCreatePC(conSize, hPipeIn_R, hPipeOut_W, 0, &hPC);
            if (SUCCEEDED(hr)) {
                useConPty = true;
                LogInfo(L"[Launch] ConPTY created successfully: %dx%d", conSize.X, conSize.Y);
            } else {
                LogWarn(L"[Launch] CreatePseudoConsole failed: hr=0x%08lX", (DWORD)hr);
            }
        } else {
            LogWarn(L"[Launch] CreatePipe for ConPTY failed: err=%lu", GetLastError());
        }
        if (hPipeIn_R)  { CloseHandle(hPipeIn_R);  hPipeIn_R  = nullptr; }
        if (hPipeOut_W) { CloseHandle(hPipeOut_W); hPipeOut_W = nullptr; }
        if (!useConPty) {
            if (hPipeIn_W)  { CloseHandle(hPipeIn_W);  hPipeIn_W  = nullptr; }
            if (hPipeOut_R) { CloseHandle(hPipeOut_R); hPipeOut_R = nullptr; }
        }
    }

    // When sharing parent console (no ConPTY, no new console), the PARENT must
    // set the console to full raw mode before launching the child. AppContainer
    // processes cannot call SetConsoleMode (even with LowBoxConsoleEnabled=1),
    // so the child's setRawMode() will silently fail. By pre-setting raw mode
    // here, the console is already in the state the TUI needs:
    //   Input:  ENABLE_VIRTUAL_TERMINAL_INPUT only (no line buffer, no echo)
    //   Output: ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
    //           | DISABLE_NEWLINE_AUTO_RETURN
    if (!useConPty && !UseNewConsole && WaitForExit) {
        LogInfo(L"[Launch] Setting console to raw mode for child TUI (AppContainer cannot SetConsoleMode)...");
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hStdin != INVALID_HANDLE_VALUE && GetConsoleMode(hStdin, &savedInputMode)) {
            // Raw mode: ONLY VT input. Disables ENABLE_LINE_INPUT, ENABLE_ECHO_INPUT,
            // ENABLE_PROCESSED_INPUT so each keypress (including Enter) is delivered
            // immediately as a VT sequence to the child process.
            DWORD newMode = ENABLE_VIRTUAL_TERMINAL_INPUT;
            if (SetConsoleMode(hStdin, newMode)) {
                inputModeChanged = true;
                LogInfo(L"[Launch] Console input: raw mode set (0x%lX -> 0x%lX)", savedInputMode, newMode);
            } else {
                LogWarn(L"[Launch] Failed to set raw input mode: err=%lu", GetLastError());
                // Fallback: try just adding VT flag
                newMode = savedInputMode | ENABLE_VIRTUAL_TERMINAL_INPUT;
                if (SetConsoleMode(hStdin, newMode)) {
                    inputModeChanged = true;
                    LogWarn(L"[Launch] Fallback: added VT input flag (0x%lX -> 0x%lX)", savedInputMode, newMode);
                }
            }
        }
        if (hStdout != INVALID_HANDLE_VALUE && GetConsoleMode(hStdout, &savedOutputMode)) {
            DWORD newMode = ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
            if (SetConsoleMode(hStdout, newMode)) {
                outputModeChanged = true;
                LogInfo(L"[Launch] Console output: VT mode set (0x%lX -> 0x%lX)", savedOutputMode, newMode);
            } else {
                LogWarn(L"[Launch] Failed to set VT output mode: err=%lu", GetLastError());
            }
        }
    }

    if (UseNewConsole) LogInfo(L"[Launch] Using CREATE_NEW_CONSOLE mode.");
    else if (useConPty) LogInfo(L"[Launch] Using ConPTY pseudoconsole for child process.");
    else LogInfo(L"[Launch] Sharing current console with child process.");

    DWORD attributeCount = 1;
    if (LaunchAsLpac) ++attributeCount;
    if (NoWin32k) ++attributeCount;
    if (useConPty) ++attributeCount;

    LogDebug(L"[Launch] Proc thread attribute count: %lu", attributeCount);

    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, attributeCount, 0, &attrListSize);

    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attrListSize));
    if (!attrList) {
        LogError(L"[Launch] HeapAlloc failed for attribute list (%llu bytes)", (unsigned long long)attrListSize);
        return ERROR_OUTOFMEMORY;
    }

    STARTUPINFOEXW si{}; PROCESS_INFORMATION pi{};
    SECURITY_CAPABILITIES sc{};
    DWORD allPackagesPolicy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    DWORD64 mitigationPolicy = 0;
    sc.AppContainerSid = packageSid;
    sc.Capabilities = CapabilityList.data();
    sc.CapabilityCount = static_cast<DWORD>(CapabilityList.size());

    LogDebug(L"[Launch] Security capabilities: SID=%p, CapCount=%lu", packageSid, sc.CapabilityCount);

    do {
        if (!InitializeProcThreadAttributeList(attrList, attributeCount, 0, &attrListSize)) {
            result = GetLastError();
            LogError(L"[Launch] InitializeProcThreadAttributeList failed: err=%lu", result);
            break;
        }
        if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                       &sc, sizeof(sc), nullptr, nullptr)) {
            result = GetLastError();
            LogError(L"[Launch] UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed: err=%lu", result);
            break;
        }
        if (LaunchAsLpac) {
            if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                                           &allPackagesPolicy, sizeof(allPackagesPolicy), nullptr, nullptr)) {
                result = GetLastError();
                LogError(L"[Launch] UpdateProcThreadAttribute(ALL_APP_PACKAGES_POLICY) failed: err=%lu", result);
                break;
            }
            LogDebug(L"[Launch] LPAC policy set.");
        }
        if (NoWin32k) {
            mitigationPolicy = PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
            if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                           &mitigationPolicy, sizeof(mitigationPolicy), nullptr, nullptr)) {
                result = GetLastError();
                LogError(L"[Launch] UpdateProcThreadAttribute(MITIGATION_POLICY) failed: err=%lu", result);
                break;
            }
            LogDebug(L"[Launch] Win32k lockdown mitigation set.");
        }
        if (useConPty && hPC) {
            if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                           hPC, sizeof(hPC), nullptr, nullptr)) {
                result = GetLastError();
                LogError(L"[Launch] UpdateProcThreadAttribute(PSEUDOCONSOLE) failed: err=%lu", result);
                break;
            }
            LogDebug(L"[Launch] Pseudoconsole attribute set.");
        }

        si.StartupInfo.cb = sizeof(si);
        si.lpAttributeList = attrList;
        DWORD createFlags = EXTENDED_STARTUPINFO_PRESENT;
        LPVOID envBlock = nullptr;
        if (!g_ChildEnv.empty()) { envBlock = g_ChildEnv.data(); createFlags |= CREATE_UNICODE_ENVIRONMENT; }
        if (UseNewConsole && !useConPty) createFlags |= CREATE_NEW_CONSOLE;

        LogInfo(L"[Launch] Calling CreateProcessAsUserW (flags=0x%08lX, envBlock=%ls)...",
                createFlags, envBlock ? L"custom" : L"inherited");

        if (!CreateProcessAsUserW(nullptr, nullptr, ExeToLaunch, nullptr, nullptr, FALSE,
                                  createFlags, envBlock, nullptr, &si.StartupInfo, &pi)) {
            result = GetLastError();
            LogError(L"[Launch] CreateProcessAsUserW FAILED: err=%lu", result);

            // Provide diagnostic info for common errors
            if (result == ERROR_ACCESS_DENIED)
                LogError(L"[Launch] Hint: ACCESS_DENIED - check if the exe is accessible from the AppContainer profile.");
            else if (result == ERROR_FILE_NOT_FOUND)
                LogError(L"[Launch] Hint: FILE_NOT_FOUND - verify the exe path is correct.");
            else if (result == ERROR_ELEVATION_REQUIRED)
                LogError(L"[Launch] Hint: ELEVATION_REQUIRED - the target exe requires admin privileges.");
            break;
        }

        wprintf(L"Successfully started AppContainer process, pid: %lu\r\n", pi.dwProcessId);
        LogInfo(L"[Launch] Process created: PID=%lu, TID=%lu", pi.dwProcessId, pi.dwThreadId);
        result = ERROR_SUCCESS;

        // Hide parent console window when child has its own console (newConsole=true).
        // Only hide if parent owns the console (double-click scenario), not if
        // launched from an existing terminal (would hide user's terminal!).
        if (HideParentConsole && UseNewConsole && WaitForExit) {
            DWORD pids[16] = {};
            DWORD procCount = GetConsoleProcessList(pids, _countof(pids));
            LogDebug(L"[Launch] Console process count: %lu", procCount);
            if (procCount <= 1) {
                // Only this process uses the console → safe to hide (double-click)
                HWND hwnd = GetConsoleWindow();
                if (hwnd) {
                    ShowWindow(hwnd, SW_HIDE);
                    LogInfo(L"[Launch] Parent console window hidden (standalone launch).");
                }
            } else {
                LogDebug(L"[Launch] Running inside existing terminal (%lu processes), keeping parent console visible.", procCount);
            }
        }

        if (useConPty) {
            LogDebug(L"[Launch] Setting up ConPTY relay threads...");
            HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
            HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
            if (GetConsoleMode(hStdin, &savedInputMode)) {
                SetConsoleMode(hStdin, ENABLE_VIRTUAL_TERMINAL_INPUT);
                inputModeChanged = true;
                LogDebug(L"[Launch] Console input mode: 0x%lX -> 0x%lX", savedInputMode, (DWORD)ENABLE_VIRTUAL_TERMINAL_INPUT);
            }
            if (GetConsoleMode(hStdout, &savedOutputMode)) {
                DWORD newMode = savedOutputMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
                SetConsoleMode(hStdout, newMode);
                outputModeChanged = true;
                LogDebug(L"[Launch] Console output mode: 0x%lX -> 0x%lX", savedOutputMode, newMode);
            }
            hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            hRelayOut = CreateThread(nullptr, 0, ConPtyOutputRelay, hPipeOut_R, 0, nullptr);
            inputCtx.hPipeWrite = hPipeIn_W;
            inputCtx.hStopEvent = hStopEvent;
            hRelayIn = CreateThread(nullptr, 0, ConPtyInputRelay, &inputCtx, 0, nullptr);
            LogInfo(L"[Launch] ConPTY relay threads started.");
        }

        if (WaitForExit) {
            LogInfo(L"[Launch] Waiting for child process (PID=%lu) to exit...", pi.dwProcessId);
            DWORD waitStart = GetTickCount();
            WaitForSingleObject(pi.hProcess, INFINITE);
            DWORD waitElapsed = GetTickCount() - waitStart;

            DWORD code = 0;
            if (GetExitCodeProcess(pi.hProcess, &code)) {
                result = code;
                LogInfo(L"[Launch] Child process exited: code=%lu (0x%08lX), runtime=%lu ms",
                        code, code, waitElapsed);
            } else {
                result = GetLastError();
                LogWarn(L"[Launch] GetExitCodeProcess failed: err=%lu, runtime=%lu ms", result, waitElapsed);
            }

            if (useConPty) {
                LogDebug(L"[Launch] Stopping ConPTY relay threads...");
                if (hStopEvent) SetEvent(hStopEvent);
                if (hPC) { g_pfnClosePC(hPC); hPC = nullptr; }
                if (hRelayOut) { WaitForSingleObject(hRelayOut, 5000); CloseHandle(hRelayOut); hRelayOut = nullptr; }
                if (hRelayIn)  { WaitForSingleObject(hRelayIn, 2000);  CloseHandle(hRelayIn);  hRelayIn  = nullptr; }
                if (hPipeIn_W)  { CloseHandle(hPipeIn_W);  hPipeIn_W  = nullptr; }
                if (hPipeOut_R) { CloseHandle(hPipeOut_R); hPipeOut_R = nullptr; }
                if (hStopEvent) { CloseHandle(hStopEvent); hStopEvent = nullptr; }
                if (inputModeChanged) {
                    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), savedInputMode);
                    LogDebug(L"[Launch] Restored console input mode: 0x%lX", savedInputMode);
                }
                if (outputModeChanged) {
                    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), savedOutputMode);
                    LogDebug(L"[Launch] Restored console output mode: 0x%lX", savedOutputMode);
                }
                LogInfo(L"[Launch] ConPTY relay threads stopped, console modes restored.");
            } else if (inputModeChanged || outputModeChanged) {
                // Restore shared console VT mode
                if (inputModeChanged) {
                    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), savedInputMode);
                    LogDebug(L"[Launch] Restored console input mode: 0x%lX", savedInputMode);
                }
                if (outputModeChanged) {
                    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), savedOutputMode);
                    LogDebug(L"[Launch] Restored console output mode: 0x%lX", savedOutputMode);
                }
                LogInfo(L"[Launch] Shared console modes restored.");
            }
        } else {
            LogInfo(L"[Launch] Not waiting for child (wait=false). Parent will proceed to cleanup.");
        }

        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
    } while (false);

    if (attrList) { DeleteProcThreadAttributeList(attrList); HeapFree(GetProcessHeap(), 0, attrList); }
    if (hPC) g_pfnClosePC(hPC);
    if (hPipeIn_W) CloseHandle(hPipeIn_W);
    if (hPipeOut_R) CloseHandle(hPipeOut_R);
    if (hStopEvent) CloseHandle(hStopEvent);

    LogDebug(L"[Launch] LaunchProcess returning: %lu", result);
    return result;
}

// ========================================================================
// Network Filter URL Parsing
// ========================================================================
static std::vector<std::wstring> ParseNetworkFilterUrls(const std::wstring& raw) {
    std::vector<std::wstring> result;
    if (raw.empty()) return result;

    // 支持分号和逗号分隔
    std::wstring current;
    for (size_t i = 0; i < raw.size(); ++i) {
        wchar_t ch = raw[i];
        if (ch == L';' || ch == L',') {
            std::wstring trimmed = TrimCopy(current);
            if (!trimmed.empty()) {
                result.push_back(trimmed);
            }
            current.clear();
        } else {
            current += ch;
        }
    }
    std::wstring trimmed = TrimCopy(current);
    if (!trimmed.empty()) {
        result.push_back(trimmed);
    }
    return result;
}

// ========================================================================
// Exe Dir / INI Config
// ========================================================================
static std::wstring GetExeDir() {
    wchar_t path[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"";
    for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
        if (path[i] == L'\\' || path[i] == L'/') { path[i + 1] = L'\0'; break; }
    }
    return std::wstring(path);
}

static std::wstring ReadIniString(const std::wstring& iniPath, const wchar_t* key) {
    const DWORD kMax = 32767;
    std::vector<wchar_t> buf(kMax + 1);
    DWORD got = GetPrivateProfileStringW(L"App", key, L"", buf.data(), kMax, iniPath.c_str());
    return std::wstring(buf.data(), got);
}

static bool IniBoolFromString(const std::wstring& s, bool defVal = false) {
    if (s.empty()) return defVal;
    std::wstring t = TrimCopy(s);
    for (auto& ch : t) ch = static_cast<wchar_t>(towlower(ch));
    if (t == L"1" || t == L"true" || t == L"yes" || t == L"on") return true;
    if (t == L"0" || t == L"false" || t == L"no" || t == L"off") return false;
    return defVal;
}

static bool LoadConfigFromIniIfNoArgs(int argc) {
    if (argc > 1) {
        LogDebug(L"[Config] CLI args present (argc=%d), skipping INI load.", argc);
        return false;
    }
    std::wstring dir = GetExeDir();
    if (dir.empty()) return false;
    std::wstring ini = dir + L"config.ini";
    DWORD attrs = GetFileAttributesW(ini.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        LogDebug(L"[Config] No config.ini found at: %ls", ini.c_str());
        return false;
    }

    LogInfo(L"[Config] Loading config from: %ls", ini.c_str());
    CapabilityList.clear(); AllowedPaths.clear(); EnvOverrides.clear();
    PathPrependEntries.clear(); g_ChildEnv.clear();

    auto moniker = TrimCopy(ReadIniString(ini, L"moniker"));
    if (!moniker.empty()) { PackageMoniker = moniker; LogInfo(L"[Config] moniker = %ls", moniker.c_str()); }
    auto exe = TrimCopy(ReadIniString(ini, L"exe"));
    if (!exe.empty()) {
        g_CmdLineBuf.assign(exe.begin(), exe.end());
        g_CmdLineBuf.push_back(L'\0');
        ExeToLaunch = g_CmdLineBuf.data();
        LogInfo(L"[Config] exe = %ls", exe.c_str());
    }
    auto disp = TrimCopy(ReadIniString(ini, L"displayName"));
    if (!disp.empty()) { PackageDisplayName = disp; LogInfo(L"[Config] displayName = %ls", disp.c_str()); }
    auto caps = ReadIniString(ini, L"capabilities");
    if (!caps.empty()) { ParseCapabilityListFromArg(caps.c_str()); LogInfo(L"[Config] capabilities loaded (%llu total)", (unsigned long long)CapabilityList.size()); }
    auto allowPaths = ReadIniString(ini, L"allowPaths");
    if (!allowPaths.empty()) { ParseAllowedPathListFromArg(allowPaths.c_str()); }
    auto env = ReadIniString(ini, L"env");
    if (!env.empty()) { ParseEnvListFromArg(env.c_str()); }
    auto prepend = ReadIniString(ini, L"pathPrepend");
    if (!prepend.empty()) { ParsePathPrependListFromArg(prepend.c_str()); }

    auto lowIntegrity = ReadIniString(ini, L"lowIntegrityOnPaths");
    if (!lowIntegrity.empty()) PathLowIntegrity = IniBoolFromString(lowIntegrity, PathLowIntegrity);
    auto cleanup = ReadIniString(ini, L"cleanupSubdirs");
    if (!cleanup.empty()) CleanupAllowedSubdirs = IniBoolFromString(cleanup, CleanupAllowedSubdirs);
    WaitForExit = IniBoolFromString(ReadIniString(ini, L"wait"), WaitForExit);
    RetainProfile = IniBoolFromString(ReadIniString(ini, L"retainProfile"), RetainProfile);
    LaunchAsLpac = IniBoolFromString(ReadIniString(ini, L"lpac"), LaunchAsLpac);
    NoWin32k = IniBoolFromString(ReadIniString(ini, L"noWin32k"), NoWin32k);
    UseNewConsole = IniBoolFromString(ReadIniString(ini, L"newConsole"), UseNewConsole);
    UseConPty = IniBoolFromString(ReadIniString(ini, L"conpty"), UseConPty);
    HideParentConsole = IniBoolFromString(ReadIniString(ini, L"hideParentConsole"), HideParentConsole);
    g_LogEnabled = IniBoolFromString(ReadIniString(ini, L"log"), g_LogEnabled);

    // --- Network Filter config ---
    g_NetworkFilterEnabled = IniBoolFromString(
        ReadIniString(ini, L"networkFilterEnabled"), g_NetworkFilterEnabled);

    auto nfPort = TrimCopy(ReadIniString(ini, L"networkFilterPort"));
    if (!nfPort.empty()) {
        int p = _wtoi(nfPort.c_str());
        if (p > 0 && p <= 65535) {
            g_NetworkFilterPort = p;
        } else {
            LogWarn(L"[Config] Invalid networkFilterPort: %ls, using default %d",
                    nfPort.c_str(), g_NetworkFilterPort);
        }
    }

    g_NetworkFilterAllowedUrls = TrimCopy(ReadIniString(ini, L"networkFilterAllowedUrls"));

    LogInfo(L"[Config] networkFilter: enabled=%d, port=%d, allowedUrls=%ls",
            g_NetworkFilterEnabled ? 1 : 0, g_NetworkFilterPort,
            g_NetworkFilterAllowedUrls.empty() ? L"(none)" : g_NetworkFilterAllowedUrls.c_str());

    LogInfo(L"[Config] Final flags: wait=%d, retainProfile=%d, lpac=%d, noWin32k=%d, "
            L"lowIntegrityOnPaths=%d, cleanupSubdirs=%d, newConsole=%d, conpty=%d, hideParent=%d, log=%d, networkFilter=%d",
            WaitForExit?1:0, RetainProfile?1:0, LaunchAsLpac?1:0, NoWin32k?1:0,
            PathLowIntegrity?1:0, CleanupAllowedSubdirs?1:0, UseNewConsole?1:0, UseConPty?1:0, HideParentConsole?1:0, g_LogEnabled?1:0, g_NetworkFilterEnabled?1:0);
    return true;
}

// ========================================================================
// Network Filter Plugin Integration
// ========================================================================
static bool InitializeNetworkFilter() {
    if (!g_NetworkFilterEnabled) {
        LogDebug(L"[NetworkFilter] Disabled, skipping initialization.");
        return true;  // Not an error
    }

    // Parse allowed domains
    auto domains = ParseNetworkFilterUrls(g_NetworkFilterAllowedUrls);
    if (domains.empty()) {
        LogWarn(L"[NetworkFilter] Enabled but no allowed URLs configured. "
                L"All network requests will be BLOCKED.");
    }

    // Configure allowed domains
    NetworkFilterPlugin::SetAllowedDomains(domains);

    // Start the proxy
    if (!NetworkFilterPlugin::Initialize(g_NetworkFilterPort)) {
        LogError(L"[NetworkFilter] Failed to initialize proxy on port %d", g_NetworkFilterPort);
        return false;
    }

    LogInfo(L"[NetworkFilter] Proxy started on %ls",
            NetworkFilterPlugin::GetProxyUrl().c_str());

    return true;
}

static void ShutdownNetworkFilter() {
    if (g_NetworkFilterEnabled && NetworkFilterPlugin::IsRunning()) {
        LONG allows = InterlockedCompareExchange(&g_ProxyAllowCount, 0, 0);
        LONG blocks = InterlockedCompareExchange(&g_ProxyBlockCount, 0, 0);
        LogInfo(L"[NetworkFilter] Shutting down proxy... (session: %ld allowed, %ld blocked)", allows, blocks);
        NetworkFilterPlugin::Shutdown();
        LogInfo(L"[NetworkFilter] Proxy stopped.");
    }
}

static void InjectProxyEnvVars() {
    if (!g_NetworkFilterEnabled || !NetworkFilterPlugin::IsRunning()) {
        return;
    }

    std::wstring proxyUrl = NetworkFilterPlugin::GetProxyUrl();

    // Set standard proxy environment variables (both cases for compatibility)
    UpsertEnvOverride(L"HTTP_PROXY",  proxyUrl);
    UpsertEnvOverride(L"HTTPS_PROXY", proxyUrl);
    UpsertEnvOverride(L"http_proxy",  proxyUrl);
    UpsertEnvOverride(L"https_proxy", proxyUrl);

    // Exclude localhost to prevent proxy self-loop
    UpsertEnvOverride(L"NO_PROXY",  L"localhost,127.0.0.1");
    UpsertEnvOverride(L"no_proxy",  L"localhost,127.0.0.1");

    LogInfo(L"[NetworkFilter] Injected proxy env vars: %ls", proxyUrl.c_str());
}

// ========================================================================
// Console Control Handler
// ========================================================================
static BOOL WINAPI OnConsoleCtrl(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_CLOSE_EVENT: case CTRL_LOGOFF_EVENT: case CTRL_SHUTDOWN_EVENT:
        LogWarn(L"[Console] Close/logoff/shutdown event (type=%lu). Cleaning up...", ctrlType);
        ShutdownNetworkFilter();
        CleanupBunVirtualDrive();
        RestoreSavedSecurityOnce();
        LogInfo(L"[Console] Cleanup complete for console event %lu.", ctrlType);
        return TRUE;
    default:
        return FALSE;
    }
}

// ========================================================================
// Entry Point
// ========================================================================
int wmain(int argc, WCHAR** argv) {
    DWORD result = ERROR_SUCCESS;
    PSID appContainerSid = nullptr;
    DWORD lowBoxConsoleEnabled = 1;

    if (!SetConsoleCtrlHandler(OnConsoleCtrl, TRUE))
        wprintf(L"[Warn] SetConsoleCtrlHandler failed: err=%lu\r\n", GetLastError());

    // Parse config and arguments FIRST to determine if logging is enabled.
    // g_LogEnabled defaults to false; set via config.ini "log=true" or CLI "-g".
    LoadConfigFromIniIfNoArgs(argc);
    if (!ParseArguments(argc, argv)) { SetConsoleCtrlHandler(OnConsoleCtrl, FALSE); return 0; }
    if (PackageMoniker.empty() || ExeToLaunch == nullptr) {
        wprintf(L"[Error] Missing required parameters: moniker or exe\r\n");
        PrintUsage(); SetConsoleCtrlHandler(OnConsoleCtrl, FALSE); return 0;
    }

    // Now that g_LogEnabled is known, initialize log file and emit startup banner.
    InitLogFile();

    LogInfo(L"========================================");
    LogInfo(L"LaunchAppContainer started (PID=%lu)", GetCurrentProcessId());
    LogInfo(L"========================================");
    if (g_LogEnabled && g_LogFile != INVALID_HANDLE_VALUE) {
        LogInfo(L"[Init] Log file: %ls", g_LogFilePath.c_str());
    }

    // Log system info
    {
        LogDebug(L"[Init] argc=%d", argc);
        for (int i = 0; i < argc; ++i) {
            LogDebug(L"[Init] argv[%d] = '%ls'", i, argv[i]);
        }
    }

    LogInfo(L"[Init] Configuration summary:");
    LogInfo(L"[Init]   Moniker:      %ls", PackageMoniker.c_str());
    LogInfo(L"[Init]   Exe:          %ls", ExeToLaunch);
    LogInfo(L"[Init]   DisplayName:  %ls", PackageDisplayName.empty() ? L"(same as moniker)" : PackageDisplayName.c_str());
    LogInfo(L"[Init]   Capabilities: %llu", (unsigned long long)CapabilityList.size());
    LogInfo(L"[Init]   AllowedPaths: %llu", (unsigned long long)AllowedPaths.size());
    for (size_t i = 0; i < AllowedPaths.size(); ++i) {
        LogInfo(L"[Init]     [%llu] %ls", (unsigned long long)i, AllowedPaths[i].c_str());
    }
    LogInfo(L"[Init]   EnvOverrides: %llu", (unsigned long long)EnvOverrides.size());
    LogInfo(L"[Init]   PathPrepends: %llu", (unsigned long long)PathPrependEntries.size());

    ResolveExePathIfSubst();
    ApplyDefaultOpenCodeEnvPaths();
    ApplyBunOpenTuiCompatibility();
    AutoEnableWaitForTuiIfNeeded();
    FixShellForAppContainer();

    if (WaitForExit) {
        UpsertEnvOverride(L"TERM", L"xterm-256color");
        UpsertEnvOverride(L"COLORTERM", L"truecolor");
        LogDebug(L"[Init] Added TERM/COLORTERM env overrides for wait mode.");
    }

    // NOTE: Do NOT build the child env block here. PrepareBunVirtualDrive()
    // may add PATH prepends and env overrides that must be captured.
    // BuildChildEnvBlockFromOverrides() is called after PrepareBunVirtualDrive().

    if (RegSetKeyValueW(HKEY_CURRENT_USER, L"Console", L"LowBoxConsoleEnabled",
                        REG_DWORD, &lowBoxConsoleEnabled, sizeof(lowBoxConsoleEnabled)) != ERROR_SUCCESS)
        LogWarn(L"[Init] Failed to set LowBoxConsoleEnabled registry key.");
    else
        LogDebug(L"[Init] LowBoxConsoleEnabled registry key set.");

    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    LogInfo(L"[Init] Console code page set to UTF-8 (65001).");

    // ================================================================
    // Network Filter Plugin: Initialize proxy before child process
    // ================================================================
    if (g_NetworkFilterEnabled) {
        LogInfo(L"[Phase] Initializing Network Filter Plugin...");
        if (!InitializeNetworkFilter()) {
            LogError(L"[Phase] Network filter initialization failed. Aborting.");
            SetConsoleCtrlHandler(OnConsoleCtrl, FALSE);
            CloseLogFile();
            return 1;
        }
        // Initialize separate proxy log file
        InitProxyLogFile();
        if (g_ProxyLogFile != INVALID_HANDLE_VALUE) {
            LogInfo(L"[Phase] Proxy log file: %ls", g_ProxyLogFilePath.c_str());
        }
        // Inject HTTP_PROXY / HTTPS_PROXY into env overrides.
        // Must be done BEFORE BuildChildEnvBlockFromOverrides().
        InjectProxyEnvVars();
    }

    // ================================================================
    // AppContainer Sandbox
    // ================================================================
    LogInfo(L"[Phase] Creating AppContainer profile...");
    result = CreateAppContainerProfileWithMoniker(&appContainerSid);
    if (result != ERROR_SUCCESS) {
        LogError(L"[Phase] Failed to create AppContainer profile: err=%lu", result);
        goto Cleanup;
    }

    if (!AllowedPaths.empty()) {
        LogInfo(L"[Phase] Granting access to allowed paths...");
        GrantAccessToAllowedPaths(appContainerSid);
    }

    // Prepare Bun virtual B: drive
    LogInfo(L"[Phase] Checking/preparing Bun virtual drive...");
    PrepareBunVirtualDrive(appContainerSid);
    atexit(AtExitCleanupBunDrive);
    SetUnhandledExceptionFilter(BunDriveCrashHandler);
    LogDebug(L"[Phase] atexit and crash handlers registered for B: drive cleanup.");

    // Build child environment block AFTER PrepareBunVirtualDrive() so that
    // any PATH prepends and env overrides added during BunVFS setup are included.
    if (!EnvOverrides.empty() || !PathPrependEntries.empty()) {
        LogInfo(L"[Phase] Building child environment block (post-BunVFS)...");
        BuildChildEnvBlockFromOverrides();
    }

    LogInfo(L"[Phase] Launching child process...");
    result = LaunchProcess(appContainerSid);
    LogInfo(L"[Phase] Child process finished with result: %lu (0x%08lX)", result, result);

    if (CleanupAllowedSubdirs && (WaitForExit || result != ERROR_SUCCESS)) {
        LogInfo(L"[Phase] Cleaning subdirectories under allowed paths...");
        CleanupAllowedPathSubdirs();
    }

    if (InterlockedCompareExchange(&g_PathAclModified, 0, 0) == 1) {
        if (WaitForExit || result != ERROR_SUCCESS) {
            LogInfo(L"[Phase] Reverting ACL/permissions...");
            RestoreSavedSecurityOnce();
        } else {
            LogDebug(L"[Phase] ACLs were modified but wait=false and process succeeded. Deferring restore.");
        }
    }

Cleanup:
    LogInfo(L"[Phase] Entering cleanup...");
    ShutdownNetworkFilter();

    // Remove B: drive mapping
    CleanupBunVirtualDrive();

    if (result != ERROR_SUCCESS && InterlockedCompareExchange(&g_PathAclModified, 0, 0) == 1) {
        LogInfo(L"[Phase] Error path: restoring ACLs...");
        RestoreSavedSecurityOnce();
    }
    if (WaitForExit && !RetainProfile && g_ProfileWasCreated) {
        LogInfo(L"[Phase] Deleting AppContainer profile...");
        DeleteAppContainerProfileWithMoniker();
    } else if (RetainProfile) {
        LogInfo(L"[Phase] Retaining AppContainer profile (retainProfile=true).");
    }
    if (appContainerSid) { FreeSid(appContainerSid); appContainerSid = nullptr; }

    SetConsoleCtrlHandler(OnConsoleCtrl, FALSE);

    LogInfo(L"========================================");
    LogInfo(L"LaunchAppContainer finished: result=%lu (0x%08lX)", result, result);
    LogInfo(L"========================================");
    CloseProxyLogFile();
    CloseLogFile();
    return static_cast<int>(result);
}
