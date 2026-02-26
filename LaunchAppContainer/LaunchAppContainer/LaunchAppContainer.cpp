#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <sdkddkver.h>
#include <Windows.h>
#include <UserEnv.h>
#include <sddl.h>
#include <Aclapi.h>
#include <WinSafer.h>
#include <TlHelp32.h>

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

enum class PathAccessLevel {
	ReadOnly,
	ReadExecute,
	ReadWrite,
	FullControl
};

struct AllowedPathEntry {
	std::wstring path;
	PathAccessLevel accessLevel;
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

	~SavedSecurity() {
		if (sdDacl) { LocalFree(sdDacl); sdDacl = nullptr; }
		if (sdSacl) { LocalFree(sdSacl); sdSacl = nullptr; }
	}

	SavedSecurity() = default;
	SavedSecurity(const SavedSecurity&) = delete;
	SavedSecurity& operator=(const SavedSecurity&) = delete;
	SavedSecurity(SavedSecurity&& other) noexcept
		: path(std::move(other.path)), sdDacl(other.sdDacl), dacl(other.dacl),
		hasDacl(other.hasDacl), daclProtected(other.daclProtected),
		sdSacl(other.sdSacl), sacl(other.sacl), hasSacl(other.hasSacl) {
		other.sdDacl = nullptr; other.sdSacl = nullptr;
		other.dacl = nullptr; other.sacl = nullptr;
		other.hasDacl = false; other.hasSacl = false;
	}
	SavedSecurity& operator=(SavedSecurity&& other) noexcept {
		if (this != &other) {
			if (sdDacl) LocalFree(sdDacl);
			if (sdSacl) LocalFree(sdSacl);
			path = std::move(other.path);
			sdDacl = other.sdDacl; dacl = other.dacl;
			hasDacl = other.hasDacl; daclProtected = other.daclProtected;
			sdSacl = other.sdSacl; sacl = other.sacl; hasSacl = other.hasSacl;
			other.sdDacl = nullptr; other.sdSacl = nullptr;
		}
		return *this;
	}
};

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
#ifndef PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY
#define PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY 0x00020019
#endif
#ifndef PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY
#define PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY 0x0002001A
#endif
#ifndef PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
#define PROCESS_CREATION_CHILD_PROCESS_RESTRICTED 0x01
#endif
#ifndef PROCESS_CREATION_CHILD_PROCESS_OVERRIDE
#define PROCESS_CREATION_CHILD_PROCESS_OVERRIDE 0x02
#endif
#ifndef PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_ENABLE_PROCESS_TREE
#define PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_ENABLE_PROCESS_TREE 0x01
#endif
#ifndef PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE
#define PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE 0x04
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

typedef HRESULT(WINAPI* FnCreatePseudoConsole)(COORD, HANDLE, HANDLE, DWORD, void**);
typedef void    (WINAPI* FnClosePseudoConsole)(void*);
typedef HRESULT(WINAPI* FnResizePseudoConsole)(void*, COORD);

static WCHAR* ExeToLaunch = nullptr;
static std::wstring PackageMoniker;
static std::wstring PackageDisplayName;

static std::vector<SidAttrWrap> CapabilityList;
static std::vector<AllowedPathEntry> AllowedPaths;
static std::vector<EnvKV> EnvOverrides;
static std::vector<std::wstring> PathPrependEntries;
static std::vector<SavedSecurity> g_SavedSecurity;

static std::vector<wchar_t> g_CmdLineBuf;
static std::vector<wchar_t> g_ChildEnv;

static bool WaitForExit = true;
static bool RetainProfile = false;
static bool LaunchAsLpac = false;
static bool NoWin32k = false;
static bool AllowChildProcess = false;
static bool PathLowIntegrity = true;
static bool UseRestrictedToken = true;
static int IntegrityLevel = 0;  // 0=Low(4096), 1=Medium(8192), 2=High(12288)
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

static std::wstring g_FirewallRuleBaseName;   // 防火墙规则名称前缀
static bool g_FirewallRulesAdded = false;     // 是否已添加防火墙规则

// Bun Virtual Drive (B:\~BUN) state
static volatile LONG g_BunCleanupDone = 0;
static bool g_BunDriveMapped = false;
static std::wstring g_BunStagingDir;
static std::wstring g_BunDriveTarget;
static std::vector<std::wstring> g_BunFallbackDirs;  // .bun fallback dirs to clean up

static volatile LONG g_RestoreDone = 0;
static volatile LONG g_PathAclModified = 0;

static FnCreatePseudoConsole g_pfnCreatePC = nullptr;
static FnClosePseudoConsole  g_pfnClosePC = nullptr;
static bool g_ConPtyAvailable = false;

// Log file state
static HANDLE g_LogFile = INVALID_HANDLE_VALUE;
static std::wstring g_LogFilePath;

// Proxy log file state (separate from sandbox log)
static HANDLE g_ProxyLogFile = INVALID_HANDLE_VALUE;
static std::wstring g_ProxyLogFilePath;
static volatile LONG g_ProxyAllowCount = 0;
static volatile LONG g_ProxyBlockCount = 0;

static HANDLE g_ChildProcess = nullptr;
static HANDLE g_hJob = nullptr;
static DWORD g_ChildConsoleHostPid = 0;  // 子进程的控制台宿主 PID（OpenConsole/conhost）
static DWORD g_ParentConsoleHostPid = 0;
static std::vector<DWORD> g_ConsoleHostsToCleanup;  // 本次创建的新 console host PID 列表（退出时逐个清理）


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
	}
	else {
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
	if (g_LogEnabled)wprintf(L"%ls%ls\r\n", prefix, body);

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
	}
	else {
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

		int len = (int)wcslen(summary);
		int utf8Len = WideCharToMultiByte(CP_UTF8, 0, summary, len, nullptr, 0, nullptr, nullptr);
		if (utf8Len > 0) {
			std::vector<char> utf8Buf(utf8Len);
			WideCharToMultiByte(CP_UTF8, 0, summary, len, utf8Buf.data(), utf8Len, nullptr, nullptr);
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
		if (g_LogEnabled)wprintf(L"%ls\r\n", line);
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

static bool VectorHasPathInsensitive(const std::vector<AllowedPathEntry>& list, const std::wstring& path) {
	for (const auto& item : list) {
		if (PathEqualsInsensitive(item.path, path)) {
			return true;
		}
	}
	return false;
}

static bool VectorHasPathInsensitiveWStr(const std::vector<std::wstring>& list, const std::wstring& path) {
	for (const auto& item : list) {
		if (PathEqualsInsensitive(item, path)) {
			return true;
		}
	}
	return false;
}

static bool AddAllowedPathUnique(const std::wstring& path, PathAccessLevel level = PathAccessLevel::FullControl) {
	std::wstring p = TrimCopy(path);
	if (p.empty()) return false;
	if (VectorHasPathInsensitive(AllowedPaths, p)) return false;
	AllowedPaths.push_back({ p, level });
	return true;
}

static bool AddPathPrependUnique(const std::wstring& path) {
	std::wstring p = TrimCopy(path);
	if (p.empty()) return false;
	if (VectorHasPathInsensitiveWStr(PathPrependEntries, p)) return false;
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
	std::vector<std::wstring> dirsToDelete;
	dirsToDelete.push_back(path);

	const int MAX_ITERATIONS = 100000;  // 防止异常情况下的无限循环
	int iterations = 0;

	while (!dirsToDelete.empty()) {
		if (++iterations > MAX_ITERATIONS) {
			LogWarn(L"[Cleanup] DeleteTreeNoFollow exceeded max iterations on: %ls", path.c_str());
			return ERROR_TOO_MANY_NAMES;
		}
		std::wstring currentPath = std::move(dirsToDelete.back());
		dirsToDelete.pop_back();

		DWORD attrs = GetFileAttributesW(currentPath.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES) {
			DWORD e = GetLastError();
			if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) continue;
			return e;
		}

		if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
			ClearReadOnlyAttributeIfSet(currentPath);
			if (DeleteFileW(currentPath.c_str())) continue;
			DWORD e = GetLastError();
			if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) continue;
			return e;
		}

		if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
			ClearReadOnlyAttributeIfSet(currentPath);
			if (RemoveDirectoryW(currentPath.c_str())) continue;
			DWORD e = GetLastError();
			if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) continue;
			return e;
		}

		std::wstring search = currentPath;
		if (!search.empty() && search.back() != L'\\') search.push_back(L'\\');
		search.append(L"*");

		WIN32_FIND_DATAW fd{};
		HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
		if (hFind != INVALID_HANDLE_VALUE) {
			std::vector<std::wstring> subItems;
			do {
				if (IsDotOrDotDot(fd.cFileName)) continue;
				std::wstring child = currentPath;
				if (!child.empty() && child.back() != L'\\') child.push_back(L'\\');
				child.append(fd.cFileName);
				subItems.push_back(std::move(child));
			} while (FindNextFileW(hFind, &fd));

			DWORD e = GetLastError();
			FindClose(hFind);
			if (e != ERROR_NO_MORE_FILES) {
				return e;
			}

			if (subItems.empty()) {
				// 目录已空（只有 . 和 ..），直接删除
				ClearReadOnlyAttributeIfSet(currentPath);
				if (!RemoveDirectoryW(currentPath.c_str())) {
					DWORD re = GetLastError();
					if (re != ERROR_FILE_NOT_FOUND && re != ERROR_PATH_NOT_FOUND) {
						return re;
					}
				}
			}
			else {
				// 目录非空：先推回自身，再推入子项
				// 栈是 LIFO，子项会先处理，最后轮到空目录被删除
				dirsToDelete.push_back(currentPath);
				for (auto& item : subItems) {
					dirsToDelete.push_back(std::move(item));
				}
			}

		}
		else {
			DWORD e = GetLastError();
			if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
				return e;
			}
			ClearReadOnlyAttributeIfSet(currentPath);
			if (!RemoveDirectoryW(currentPath.c_str())) {
				e = GetLastError();
				if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
					return e;
				}
			}
		}
	}

	return ERROR_SUCCESS;
}

static void DeleteSubdirectoriesOfRoot(const std::wstring& root) {
	std::wstring r = NormalizePathForCompare(root);
	if (r.empty() || r.size() <= 3) {
		LogWarn(L"[Cleanup] Refuse to clean subdirs of drive root: %ls", root.c_str());
		return;
	}
	if (!DirectoryExists(r)) {
		return;
	}

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

		DWORD dw = DeleteTreeNoFollow(child);
		if (dw == ERROR_SUCCESS) {
			++deletedCount;
		}
		else {
			LogWarn(L"[Cleanup] Failed to delete subdir: %ls (%lu)", child.c_str(), dw);
			++failedCount;
		}
	} while (FindNextFileW(hFind, &fd));

	FindClose(hFind);
}

static void CleanupAllowedPathSubdirs() {
	for (const auto& entry : AllowedPaths) {
		DeleteSubdirectoriesOfRoot(entry.path);
	}
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
	}
	else {
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
	}
	else {
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
	}
	else {
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
		return;
	}

	// Case 2: SHELL not set -> OpenCode/Node will search PATH and find bash.exe -> preempt
	if (currentShell.empty()) {
		UpsertEnvOverride(L"SHELL", safeShell);
		return;
	}

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

	std::wstring resolved;
	if (ResolveSubstPath(image, &resolved)) {
		if (!PathEqualsInsensitive(image, resolved)) {
			LogWarn(L"[SubstResolve] Executable is on SUBST drive: '%ls' -> '%ls'", image.c_str(), resolved.c_str());

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
				}
				else {
					argsSuffix = end;
				}
			}
			else {
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
		}
	}
}

static void UpsertEnvOverride(const std::wstring& key, const std::wstring& value) {
	if (key.empty() || key.find(L'=') != std::wstring::npos) return;

	for (auto& kv : EnvOverrides) {
		if (IEquals(kv.name, key)) {
			kv.value = value;
			return;
		}
	}

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
			return;
		}
	}
	EnvOverrides.push_back(EnvKV{ key, value });
}

static void ApplyDefaultOpenCodeEnvPaths() {
	std::wstring exeDir = GetExeDir();
	if (exeDir.empty()) return;

	// Remove trailing backslash for clean paths
	while (exeDir.size() > 3 && exeDir.back() == L'\\') exeDir.pop_back();

	std::wstring baseDir = JoinPath(exeDir, L"opencode");
	std::wstring workDir = JoinPath(baseDir, L"work");
	std::wstring configDir = JoinPath(baseDir, L"config");
	std::wstring cacheDir = JoinPath(baseDir, L"cache");
	std::wstring dataDir = JoinPath(baseDir, L"data");
	std::wstring tempDir = JoinPath(baseDir, L"temp");

	// Create directories
	CreateDirectoryW(baseDir.c_str(), nullptr);
	CreateDirectoryW(workDir.c_str(), nullptr);
	CreateDirectoryW(configDir.c_str(), nullptr);
	CreateDirectoryW(cacheDir.c_str(), nullptr);
	CreateDirectoryW(dataDir.c_str(), nullptr);
	CreateDirectoryW(tempDir.c_str(), nullptr);

	// Set environment variables (user config takes priority)
	SetEnvDefaultIfAbsent(L"HOME", workDir);
	SetEnvDefaultIfAbsent(L"USERPROFILE", workDir);
	SetEnvDefaultIfAbsent(L"APPDATA", configDir);
	SetEnvDefaultIfAbsent(L"LOCALAPPDATA", dataDir);
	SetEnvDefaultIfAbsent(L"TEMP", tempDir);
	SetEnvDefaultIfAbsent(L"TMP", tempDir);
	SetEnvDefaultIfAbsent(L"XDG_CONFIG_HOME", configDir);
	SetEnvDefaultIfAbsent(L"XDG_CACHE_HOME", cacheDir);
	SetEnvDefaultIfAbsent(L"XDG_DATA_HOME", dataDir);
	SetEnvDefaultIfAbsent(L"OPENCODE_CONFIG", JoinPath(baseDir, L"opencode.json"));

	// Auto-add all subdirs to AllowedPaths
	std::wstring dirs[] = { baseDir, workDir, configDir, cacheDir, dataDir, tempDir };
	for (const auto& d : dirs) {
		if (AddAllowedPathUnique(d)) {}
	}

}

static void ApplyBunOpenTuiCompatibility() {
	if (!ExeToLaunch) return;

	std::wstring imagePath = ParseImagePathFromCommandLine(ExeToLaunch);
	bool bunDetected = LooksLikeBunImage(imagePath) || CommandLineMentionsBun(ExeToLaunch);
	if (!bunDetected) {
		return;
	}

	std::wstring bunInstall = TrimCopy(GetEnvVarCopy(L"BUN_INSTALL"));
	if (bunInstall.empty() && !imagePath.empty()) {
		std::wstring imageDir = GetParentDir(imagePath);
		if (IEquals(GetFileNamePart(imageDir), L"bin")) {
			bunInstall = GetParentDir(imageDir);
		}
	}

	if (bunInstall.empty()) {
		LogWarn(L"[BunCompat] bun detected, but BUN_INSTALL is empty. Skip auto path fix.");
		return;
	}

	bool changed = false;

	auto applyBase = [&](const std::wstring& base, PCWSTR sourceTag) {
		if (base.empty()) return;

		std::wstring rootPath = JoinPath(base, L"root");
		std::wstring binPath = JoinPath(base, L"bin");

		if (DirectoryExists(rootPath)) {
			if (AddAllowedPathUnique(rootPath)) {
				changed = true;
			}
			if (AddPathPrependUnique(rootPath)) {
				changed = true;
			}
		}

		if (DirectoryExists(binPath)) {
			if (AddPathPrependUnique(binPath)) {
				changed = true;
			}
		}
		};

	applyBase(bunInstall, L"[BunCompat]");

	std::wstring resolvedInstall;
	if (ResolveSubstPath(bunInstall, &resolvedInstall) &&
		!PathEqualsInsensitive(bunInstall, resolvedInstall) &&
		DirectoryExists(resolvedInstall)) {
		UpsertEnvOverride(L"BUN_INSTALL", resolvedInstall);
		applyBase(resolvedInstall, L"[BunCompat]");
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
			CapabilityList.emplace_back(sidInfo);
			continue;
		}

		PSID* capGroupSids = nullptr;
		DWORD capGroupSidsLen = 0;
		PSID* capSids = nullptr;
		DWORD capSidsLen = 0;

		if (DeriveCapabilitySidsFromName(cap.c_str(), &capGroupSids, &capGroupSidsLen, &capSids, &capSidsLen)) {
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

static PathAccessLevel ParseAccessLevel(const std::wstring& pathWithLevel, std::wstring& outPath) {
	outPath = pathWithLevel;

	size_t colonPos = pathWithLevel.rfind(L':');
	if (colonPos != std::wstring::npos && colonPos > 1 && colonPos + 1 < pathWithLevel.size()) {
		std::wstring levelStr = pathWithLevel.substr(colonPos + 1);
		outPath = TrimCopy(pathWithLevel.substr(0, colonPos));

		if (levelStr == L"R" || levelStr == L"r") {
			return PathAccessLevel::ReadOnly;
		}
		else if (levelStr == L"RX" || levelStr == L"rx") {
			return PathAccessLevel::ReadExecute;
		}
		else if (levelStr == L"RW" || levelStr == L"rw") {
			return PathAccessLevel::ReadWrite;
		}
		else if (levelStr == L"F" || levelStr == L"f") {
			return PathAccessLevel::FullControl;
		}
		else {
			outPath = pathWithLevel;  // ← 不是已知后缀，恢复原始路径
		}
	}

	return PathAccessLevel::FullControl;
}

static bool ParseAllowedPathList(WCHAR* paths) {
	if (!paths) return true;

	// Remove surrounding quotes if present
	std::wstring pathsStr = TrimCopy(paths);
	if (pathsStr.size() >= 2 && pathsStr.front() == L'"' && pathsStr.back() == L'"') {
		pathsStr = pathsStr.substr(1, pathsStr.size() - 2);
	}
	// Copy to mutable buffer
	std::vector<wchar_t> buf(pathsStr.begin(), pathsStr.end());
	buf.push_back(L'\0');

	WCHAR* ctx = nullptr;
	// Support both semicolon and comma as separators
	for (WCHAR* tok = wcstok_s(buf.data(), L";,", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";,", &ctx)) {
		std::wstring raw = TrimCopy(tok);
		// Remove quotes around each path
		if (raw.size() >= 2 && raw.front() == L'"' && raw.back() == L'"') {
			raw = raw.substr(1, raw.size() - 2);
		}
		if (!raw.empty()) {
			std::wstring path;
			PathAccessLevel level = ParseAccessLevel(raw, path);
			if (!path.empty()) {
				AddAllowedPathUnique(path, level);
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
		}
		else {
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
			if (AddPathPrependUnique(p)) {}
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
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] != L'-' && argv[i][0] != L'/') {
			continue;
		}

		switch (argv[i][1]) {
		case L'i':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			ExeToLaunch = argv[++i];
			break;
		case L'm':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			PackageMoniker = argv[++i];
			break;
		case L'c':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			if (!ParseCapabilityListFromArg(argv[++i])) return false;
			break;
		case L'd':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			PackageDisplayName = argv[++i];
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
		case L's': PathLowIntegrity = false; break;
		case L'w': WaitForExit = true; break;
		case L'r': RetainProfile = true; break;
		case L'l': LaunchAsLpac = true; break;
		case L'k': NoWin32k = true; break;
		case L'C': AllowChildProcess = true; break;
		case L'R': UseRestrictedToken = true; break;
		case L'x': CleanupAllowedSubdirs = true; break;
		case L'g': g_LogEnabled = true; break;
		default:
			LogWarn(L"[Args] Unknown option: %ls", argv[i]);
			break;
		}
	}

	return true;
}

// ========================================================================
// AppContainer Profile Management
// ========================================================================
static DWORD CreateAppContainerProfileWithMoniker(PSID* pAppContainerSid) {
	g_ProfileWasCreated = false;
	*pAppContainerSid = nullptr;

	PCWSTR display = PackageDisplayName.empty() ? PackageMoniker.c_str() : PackageDisplayName.c_str();

	PSID packageSid = nullptr;
	HRESULT hr = CreateAppContainerProfile(
		PackageMoniker.c_str(), display, display,
		CapabilityList.data(),
		static_cast<DWORD>(CapabilityList.size()),
		&packageSid);

	if (SUCCEEDED(hr)) {
		g_ProfileWasCreated = true;
		*pAppContainerSid = packageSid;
		return ERROR_SUCCESS;
	}

	if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
		hr = DeriveAppContainerSidFromAppContainerName(PackageMoniker.c_str(), &packageSid);
		if (SUCCEEDED(hr)) {
			*pAppContainerSid = packageSid;
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
	HRESULT hr = DeleteAppContainerProfile(PackageMoniker.c_str());
	if (FAILED(hr)) {
		DWORD err = HRESULT_CODE(hr);
		LogWarn(L"[Profile] DeleteAppContainerProfile failed: hr=0x%08lX, err=%lu", (DWORD)hr, err);
		return err;
	}
	return ERROR_SUCCESS;
}

// ========================================================================
// Security / ACL Management
// ========================================================================
static bool SidAlreadyHasAccess(PCWSTR path, PSID sid, DWORD requiredMask) {
	PSECURITY_DESCRIPTOR sd = nullptr;
	PACL dacl = nullptr;
	DWORD dw = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
		nullptr, nullptr, &dacl, nullptr, &sd);
	if (dw != ERROR_SUCCESS || !dacl) {
		if (sd) LocalFree(sd);
		return false;
	}

	ACL_SIZE_INFORMATION aclInfo{};
	if (!GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
		LocalFree(sd);
		return false;
	}

	bool found = false;
	for (DWORD i = 0; i < aclInfo.AceCount; ++i) {
		ACCESS_ALLOWED_ACE* ace = nullptr;
		if (!GetAce(dacl, i, reinterpret_cast<LPVOID*>(&ace))) continue;
		if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
		if (!EqualSid(reinterpret_cast<PSID>(&ace->SidStart), sid)) continue;

		// 检查权限掩码是否包含所需权限
		if ((ace->Mask & requiredMask) == requiredMask) {
			found = true;
			break;
		}
	}

	LocalFree(sd);
	return found;
}

// 从 PathAccessLevel 枚举映射到 ACCESS_MASK
static DWORD AccessMaskFromLevel(PathAccessLevel level) {
	switch (level) {
	case PathAccessLevel::ReadOnly:
		return FILE_GENERIC_READ;
	case PathAccessLevel::ReadExecute:
		return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
	case PathAccessLevel::ReadWrite:
		return FILE_GENERIC_READ | FILE_GENERIC_WRITE;
	case PathAccessLevel::FullControl:
	default:
		return FILE_ALL_ACCESS;
	}
}
static bool PathHasLowIntegrityLabel(PCWSTR path) {
	PSECURITY_DESCRIPTOR sd = nullptr;
	PACL sacl = nullptr;
	DWORD dw = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
		nullptr, nullptr, nullptr, &sacl, &sd);
	if (dw != ERROR_SUCCESS || !sacl) {
		if (sd) LocalFree(sd);
		return false;
	}

	ACL_SIZE_INFORMATION aclInfo{};
	if (!GetAclInformation(sacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
		LocalFree(sd);
		return false;
	}

	// 低完整性 SID: S-1-16-4096
	PSID pLowSid = nullptr;
	if (!ConvertStringSidToSid(L"S-1-16-4096", &pLowSid)) {
		LocalFree(sd);
		return false;
	}

	bool found = false;
	for (DWORD i = 0; i < aclInfo.AceCount; ++i) {
		SYSTEM_MANDATORY_LABEL_ACE* ace = nullptr;
		if (!GetAce(sacl, i, reinterpret_cast<LPVOID*>(&ace))) continue;
		if (ace->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE) continue;
		if (EqualSid(reinterpret_cast<PSID>(&ace->SidStart), pLowSid)) {
			found = true;
			break;
		}
	}

	LocalFree(pLowSid);
	LocalFree(sd);
	return found;
}
static DWORD GrantAccessToSidOnPath(PCWSTR path, PSID sid, PathAccessLevel level) {
	DWORD requiredMask = AccessMaskFromLevel(level);
	if (SidAlreadyHasAccess(path, sid, requiredMask)) {
		LogInfo(L"[ACL] SID already has required access on %ls, skipping propagation.", path);
		return ERROR_SUCCESS;
	}
	PSECURITY_DESCRIPTOR sd = nullptr;
	PACL oldDacl = nullptr;

	DWORD dw = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
		nullptr, nullptr, &oldDacl, nullptr, &sd);
	if (dw != ERROR_SUCCESS) {
		LogError(L"[ACL] GetNamedSecurityInfoW failed on %ls: err=%lu", path, dw);
		return dw;
	}

	EXPLICIT_ACCESSW ea{};
	switch (level) {
	case PathAccessLevel::ReadOnly:
		ea.grfAccessPermissions = FILE_GENERIC_READ;
		break;
	case PathAccessLevel::ReadExecute:
		ea.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
		break;
	case PathAccessLevel::ReadWrite:
		ea.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
		break;
	case PathAccessLevel::FullControl:
	default:
		ea.grfAccessPermissions = FILE_ALL_ACCESS;
		break;
	}
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
	}

	if (newDacl) LocalFree(newDacl);
	if (sd) LocalFree(sd);
	return dw;
}

static DWORD GrantFullControlToSidOnPath(PCWSTR path, PSID sid) {
	return GrantAccessToSidOnPath(path, sid, PathAccessLevel::FullControl);
}

static DWORD SetLowIntegrityLabel(PCWSTR path) {
	// ★ 快速路径：如果已有低完整性标签，跳过
	if (PathHasLowIntegrityLabel(path)) {
		LogInfo(L"[ACL] Low integrity label already set on %ls, skipping.", path);
		return ERROR_SUCCESS;
	}
	PSECURITY_DESCRIPTOR sd = nullptr;
	// S:(ML;;NW;;;LW) - Low integrity label with inheritance (OI)(CI)
	// OI = OBJECT_INHERIT_ACE, CI = CONTAINER_INHERIT_ACE
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"S:(ML;OICI;NW;;;LW)", SDDL_REVISION_1, &sd, nullptr)) {
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
	}
	else {
		LogWarn(L"[Security] Failed to backup DACL for %ls (err=%lu)", path, daclErr);
	}

	DWORD saclErr = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
		nullptr, nullptr, nullptr, &ss.sacl, &ss.sdSacl);
	if (saclErr == ERROR_SUCCESS) {
		ss.hasSacl = true;
	}
	else {
		LogWarn(L"[Security] Failed to backup Label SACL for %ls (err=%lu)", path, saclErr);
	}

	g_SavedSecurity.push_back(std::move(ss));
	return (daclErr == ERROR_SUCCESS || saclErr == ERROR_SUCCESS) ? ERROR_SUCCESS
		: (daclErr != ERROR_SUCCESS ? daclErr : saclErr);
}

static void RestoreSavedSecurity() {
	int restoredDacl = 0, restoredSacl = 0, failedDacl = 0, failedSacl = 0;

	for (auto& ss : g_SavedSecurity) {
		if (ss.hasDacl) {
			DWORD dw = RestoreDaclWithProtection(ss);
			if (dw == ERROR_SUCCESS) {
				++restoredDacl;
			}
			else {
				LogWarn(L"[Revert] Failed to restore DACL on %ls (err=%lu)", ss.path.c_str(), dw);
				++failedDacl;
			}
		}
		if (ss.hasSacl) {
			DWORD dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(ss.path.c_str()), SE_FILE_OBJECT,
				LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, ss.sacl);
			if (dw == ERROR_SUCCESS) {
				++restoredSacl;
			}
			else {
				LogWarn(L"[Revert] Failed to restore Label SACL on %ls (err=%lu)", ss.path.c_str(), dw);
				++failedSacl;
			}
		}
	}
	g_SavedSecurity.clear();

	LogInfo(L"[Revert] Security restore complete: DACL restored=%d failed=%d, SACL restored=%d failed=%d",
		restoredDacl, failedDacl, restoredSacl, failedSacl);
}

static void RestoreSavedSecurityOnce() {
	if (InterlockedCompareExchange(&g_RestoreDone, 1, 0) != 0) {
		return;
	}
	if (InterlockedCompareExchange(&g_PathAclModified, 0, 0) == 1) {
		RestoreSavedSecurity();
	}
}

static void GrantAccessToAllowedPaths(PSID appContainerSid) {
	int grantedCount = 0, skippedCount = 0, failedCount = 0;

	for (const auto& entry : AllowedPaths) {
		DWORD attrs = GetFileAttributesW(entry.path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES) {
			if (g_LogEnabled)wprintf(L"[Skip] Path not found: %ls (err=%lu)\r\n", entry.path.c_str(), GetLastError());
			LogWarn(L"[Permissions] Skip path (not found): %ls (err=%lu)", entry.path.c_str(), GetLastError());
			++skippedCount;
			continue;
		}
		if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
			if (g_LogEnabled)wprintf(L"[Skip] Not a directory: %ls (attrs=0x%08lX)\r\n", entry.path.c_str(), attrs);
			LogWarn(L"[Permissions] Skip path (not directory): %ls (attrs=0x%08lX)", entry.path.c_str(), attrs);
			++skippedCount;
			continue;
		}
		DWORD requiredMask = AccessMaskFromLevel(entry.accessLevel);
		bool daclNeeded = !SidAlreadyHasAccess(entry.path.c_str(), appContainerSid, requiredMask);
		bool saclNeeded = PathLowIntegrity && !PathHasLowIntegrityLabel(entry.path.c_str());
		if (!daclNeeded && !saclNeeded) {
			LogInfo(L"[Permissions] ACLs already correct on %ls, skipping.", entry.path.c_str());
			++skippedCount;
			continue;
		}
		SaveOriginalSecurityForPath(entry.path.c_str());
		SavedSecurity* backup = g_SavedSecurity.empty() ? nullptr : &g_SavedSecurity.back();
		bool modifiedThisPath = false;

		if (backup && backup->hasDacl) {
			DWORD dw = GrantAccessToSidOnPath(entry.path.c_str(), appContainerSid, entry.accessLevel);
			if (dw == ERROR_SUCCESS) {
				const wchar_t* levelStr = L"R";
				if (entry.accessLevel == PathAccessLevel::ReadExecute) levelStr = L"RX";
				else if (entry.accessLevel == PathAccessLevel::ReadWrite) levelStr = L"RW";
				else if (entry.accessLevel == PathAccessLevel::FullControl) levelStr = L"F";
				if (g_LogEnabled)wprintf(L"[OK] Granted (%ls) to %ls\r\n", levelStr, entry.path.c_str());
				modifiedThisPath = true;
			}
			else {
				if (g_LogEnabled)wprintf(L"[Warn] Grant failed on %ls (%lu)\r\n", entry.path.c_str(), dw);
				LogWarn(L"[Permissions] Grant failed on %ls (err=%lu)", entry.path.c_str(), dw);
				++failedCount;
			}
		}

		if (PathLowIntegrity && backup && backup->hasSacl) {
			DWORD dw = SetLowIntegrityLabel(entry.path.c_str());
			if (dw == ERROR_SUCCESS) {
				if (g_LogEnabled)wprintf(L"[OK] Low Integrity set on %ls\r\n", entry.path.c_str());
				modifiedThisPath = true;
			}
			else {
				if (g_LogEnabled)wprintf(L"[Warn] Set Low Integrity failed on %ls (%lu)\r\n", entry.path.c_str(), dw);
				if (dw == ERROR_ACCESS_DENIED)
					LogWarn(L"[Permissions] Set Low Integrity DENIED on %ls. Run elevated or set lowIntegrityOnPaths=false.", entry.path.c_str());
				else
					LogWarn(L"[Permissions] Set Low Integrity failed on %ls (err=%lu)", entry.path.c_str(), dw);
				++failedCount;
			}

			// 为低完整性进程添加明确的写入权限
			if (entry.accessLevel == PathAccessLevel::ReadWrite || entry.accessLevel == PathAccessLevel::FullControl) {
				PSID pLowIntegritySid = nullptr;
				if (ConvertStringSidToSid(L"S-1-16-4096", &pLowIntegritySid)) {
					DWORD mask = AccessMaskFromLevel(entry.accessLevel);
					if (!SidAlreadyHasAccess(entry.path.c_str(), pLowIntegritySid, mask)) {
						DWORD dwLow = GrantAccessToSidOnPath(entry.path.c_str(), pLowIntegritySid, entry.accessLevel);
						if (dwLow == ERROR_SUCCESS) {
							if (g_LogEnabled)wprintf(L"[OK] Granted Low-IL write access on %ls\r\n", entry.path.c_str());
							LogInfo(L"[Permissions] Low-IL write access granted on %ls", entry.path.c_str());
						}
						else {
							if (g_LogEnabled)wprintf(L"[Warn] Failed to grant Low-IL write access on %ls (%lu)\r\n", entry.path.c_str(), dwLow);
							LogWarn(L"[Permissions] Failed to grant Low-IL write access on %ls (err=%lu)", entry.path.c_str(), dwLow);
						}
					}
					else {
						LogInfo(L"[Permissions] Low-IL SID already has access on %ls, skipping.", entry.path.c_str());
					}
					LocalFree(pLowIntegritySid);
				}
			}
		}

		if (modifiedThisPath) {
			InterlockedExchange(&g_PathAclModified, 1);
			++grantedCount;
		}
		else {
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
	g_pfnClosePC = (FnClosePseudoConsole)GetProcAddress(hK32, "ClosePseudoConsole");
	g_ConPtyAvailable = (g_pfnCreatePC != nullptr && g_pfnClosePC != nullptr);
	if (!g_ConPtyAvailable) {
		LogWarn(L"[ConPTY] CreatePseudoConsole not available on this OS.");
	}
	return g_ConPtyAvailable;
}

static COORD GetCurrentConsoleSize() {
	CONSOLE_SCREEN_BUFFER_INFO csbi{};
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(hOut, &csbi)) {
		COORD sz;
		sz.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		sz.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
		return sz;
	}
	COORD fallback;
	fallback.X = 120;
	fallback.Y = 30;
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
			}
			else {
				break;
			}
		}

		if (j + 4 <= dataSize && memcmp(data + j, ".dll", 4) == 0) {
			size_t nameLen = (j + 4) - i;
			std::string name(reinterpret_cast<const char*>(data + i), nameLen);
			std::wstring wname(name.begin(), name.end());
			return wname;
		}
	}

	LogWarn(L"[BunVFS] DLL name pattern not found after scanning %d candidates in %llu bytes.",
		candidateCount, (unsigned long long)dataSize);
	return L"";
}

// Convert an RVA (Relative Virtual Address) to a file offset using the section table.
// Returns 0 on failure. The PE base pointer must point to a valid MZ header.
static DWORD RvaToFileOffset(const BYTE* peBase, size_t peSize, DWORD rva) {
	if (peSize < 0x40 || rva == 0) return 0;

	DWORD peOff = *reinterpret_cast<const DWORD*>(peBase + 0x3C);
	if (peOff < 0x40 || peOff + 4 + 20 > peSize) return 0;

	size_t coffOff = peOff + 4;
	WORD numSections = *reinterpret_cast<const WORD*>(peBase + coffOff + 2);
	WORD optSize = *reinterpret_cast<const WORD*>(peBase + coffOff + 16);
	size_t secTableOff = coffOff + 20 + optSize;

	if (numSections > 96 || secTableOff + numSections * 40 > peSize) return 0;

	for (WORD s = 0; s < numSections; ++s) {
		size_t sh = secTableOff + s * 40;
		DWORD secVA = *reinterpret_cast<const DWORD*>(peBase + sh + 12);
		DWORD secRawSize = *reinterpret_cast<const DWORD*>(peBase + sh + 16);
		DWORD secRawPtr = *reinterpret_cast<const DWORD*>(peBase + sh + 20);
		DWORD secVSize = *reinterpret_cast<const DWORD*>(peBase + sh + 8);

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
	}
	else if (magic == 0x020B) { // PE32+
		if (optSize < 112) return false;
		numDataDirs = *reinterpret_cast<const DWORD*>(peBase + optOff + 108);
		dataDirOff = optOff + 112;
	}
	else {
		return false;
	}
	if (numDataDirs > 16) numDataDirs = 16;

	// Export directory is data dir index 0
	if (numDataDirs < 1) return false;
	DWORD exportRVA = *reinterpret_cast<const DWORD*>(peBase + dataDirOff);
	DWORD exportSize = *reinterpret_cast<const DWORD*>(peBase + dataDirOff + 4);
	if (exportRVA == 0 || exportSize == 0) {
		return false;
	}

	DWORD exportFileOff = RvaToFileOffset(peBase, peSize, exportRVA);
	if (exportFileOff == 0 || exportFileOff + 40 > peSize) {
		return false;
	}

	// IMAGE_EXPORT_DIRECTORY structure (40 bytes)
	// Offset 24: NumberOfNames (DWORD)
	// Offset 32: AddressOfNames (DWORD RVA -> array of RVAs to name strings)
DWORD numberOfNames = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 24);
	DWORD namesRVA = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 32);

	// Also read DLL name from export dir
	DWORD dllNameRVA = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 12);
	if (dllNameRVA > 0) {
		DWORD dllNameOff = RvaToFileOffset(peBase, peSize, dllNameRVA);
		if (dllNameOff > 0 && dllNameOff + 1 < peSize) {
			const char* dn = reinterpret_cast<const char*>(peBase + dllNameOff);
			size_t maxLen = peSize - dllNameOff;
			size_t len = strnlen(dn, maxLen > 260 ? 260 : maxLen);
		}
	}

	if (outExportCount) *outExportCount = static_cast<int>(numberOfNames);

	if (numberOfNames == 0 || namesRVA == 0) return false;
	if (numberOfNames > 100000) {
		LogWarn(L"[BunVFS/Export] Suspicious export count: %lu", numberOfNames);
		return false;
	}

	DWORD namesFileOff = RvaToFileOffset(peBase, peSize, namesRVA);
	if (namesFileOff == 0 || namesFileOff + numberOfNames * 4 > peSize) {
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
			++printedCount;
		}
		else if (printedCount == 20) {
			++printedCount;
		}

		if (len == symbolLen && memcmp(name, symbolName, symbolLen) == 0) {
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
	WORD machine = *reinterpret_cast<const WORD*>(base + coffOff + 0);
	WORD numSections = *reinterpret_cast<const WORD*>(base + coffOff + 2);
	WORD optHeaderSize = *reinterpret_cast<const WORD*>(base + coffOff + 16);
	WORD characteristics = *reinterpret_cast<const WORD*>(base + coffOff + 18);

	if (!(characteristics & 0x2000)) return 0;  // IMAGE_FILE_DLL
	if (machine != 0x014C && machine != 0x8664) return 0;
	if (numSections == 0 || numSections > 96) return 0;
	if (optHeaderSize < 96) return 0;

	size_t optOff = coffOff + 20;
	if (optOff + optHeaderSize > maxLen) return 0;

	WORD optMagic = *reinterpret_cast<const WORD*>(base + optOff);
	bool isPE32Plus = (optMagic == 0x020B);
	bool isPE32 = (optMagic == 0x010B);
	if (!isPE32 && !isPE32Plus) return 0;

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
	}
	else {
		sizeOfImage = *reinterpret_cast<const DWORD*>(base + optOff + 56);
	}

	DWORD numDataDirs = 0;
	size_t dataDirOff = 0;
	if (isPE32) {
		if (optHeaderSize < 96) return 0;
		numDataDirs = *reinterpret_cast<const DWORD*>(base + optOff + 92);
		dataDirOff = optOff + 96;
	}
	else {
		if (optHeaderSize < 112) return 0;
		numDataDirs = *reinterpret_cast<const DWORD*>(base + optOff + 108);
		dataDirOff = optOff + 112;
	}
	if (numDataDirs > 16) numDataDirs = 16;

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
		DWORD rawPtr = *reinterpret_cast<const DWORD*>(base + shOff + 20);

		if (rawSize > 0 && rawPtr > 0) {
			size_t end = static_cast<size_t>(rawPtr) + rawSize;
			if (end > maxLen) return 0;
			if (end > totalSize) totalSize = end;
		}
	}

	// 2) Certificate / Authenticode table (index 4) - uses FILE OFFSET, not RVA
	if (numDataDirs > 4) {
		size_t certEntryOff = dataDirOff + 4 * 8;
		if (certEntryOff + 8 <= optOff + optHeaderSize) {
			DWORD certFileOffset = *reinterpret_cast<const DWORD*>(base + certEntryOff);
			DWORD certSize = *reinterpret_cast<const DWORD*>(base + certEntryOff + 4);
			if (certFileOffset > 0 && certSize > 0) {
				size_t certEnd = static_cast<size_t>(certFileOffset) + certSize;
				if (certEnd > maxLen) return 0;
				if (certEnd > totalSize) totalSize = certEnd;
			}
		}
	}

	// 3) Debug directory (index 6) - entries may have PointerToRawData outside sections
	if (numDataDirs > 6) {
		size_t dbgEntryOff = dataDirOff + 6 * 8;
		if (dbgEntryOff + 8 <= optOff + optHeaderSize) {
			DWORD dbgRVA = *reinterpret_cast<const DWORD*>(base + dbgEntryOff);
			DWORD dbgSize = *reinterpret_cast<const DWORD*>(base + dbgEntryOff + 4);
			if (dbgRVA > 0 && dbgSize > 0) {
				DWORD dbgFileOff = RvaToFileOffset(base, maxLen, dbgRVA);
				if (dbgFileOff > 0) {
					// Each IMAGE_DEBUG_DIRECTORY is 28 bytes
					DWORD numEntries = dbgSize / 28;
					for (DWORD d = 0; d < numEntries && dbgFileOff + d * 28 + 28 <= maxLen; ++d) {
						size_t entOff = dbgFileOff + d * 28;
						DWORD dbgDataSize = *reinterpret_cast<const DWORD*>(base + entOff + 16);
						DWORD dbgDataPtr = *reinterpret_cast<const DWORD*>(base + entOff + 24);
						if (dbgDataSize > 0 && dbgDataPtr > 0) {
							size_t dbgEnd = static_cast<size_t>(dbgDataPtr) + dbgDataSize;
							if (dbgEnd <= maxLen && dbgEnd > totalSize) {
								totalSize = dbgEnd;
							}
						}
					}
				}
			}
		}
	}

	// 4) Align total size up to FileAlignment
	size_t unalignedSize = totalSize;
	if (fileAlignment > 1) {
		totalSize = (totalSize + fileAlignment - 1) & ~(static_cast<size_t>(fileAlignment) - 1);
		if (totalSize > maxLen) totalSize = maxLen;
	}

	if (totalSize < 4096) return 0;

	return totalSize;
}

// After extraction, verify the DLL is loadable by checking key PE structures
// and also verifying that expected exports (like "setLogCallback") exist.
static bool VerifyExtractedDll(const std::wstring& dllPath, bool checkExports = true) {

	HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		LogError(L"[BunVFS/Verify] Cannot open DLL file: %ls (err=%lu)", dllPath.c_str(), GetLastError());
		return false;
	}

	LARGE_INTEGER li{};
	GetFileSizeEx(hFile, &li);
	size_t fileSize = static_cast<size_t>(li.QuadPart);

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

		// 2) DLL flag
		WORD chars = *reinterpret_cast<const WORD*>(base + peOff + 4 + 18);
		if (!(chars & 0x2000)) {
			LogError(L"[BunVFS/Verify] FAIL: IMAGE_FILE_DLL flag not set (chars=0x%04X)", chars);
			valid = false;
			goto done;
		}

		// 3) All sections' raw data must be within file bounds
		WORD numSections = *reinterpret_cast<const WORD*>(base + peOff + 4 + 2);
		WORD optSize = *reinterpret_cast<const WORD*>(base + peOff + 4 + 16);
		size_t secOff = peOff + 4 + 20 + optSize;

		for (WORD s = 0; s < numSections && secOff + s * 40 + 40 <= fileSize; ++s) {
			size_t sh = secOff + s * 40;
			char secName[9] = {};
			memcpy(secName, base + sh, 8);
			DWORD rawSize = *reinterpret_cast<const DWORD*>(base + sh + 16);
			DWORD rawPtr = *reinterpret_cast<const DWORD*>(base + sh + 20);
			if (rawSize > 0 && rawPtr > 0) {
				size_t end = static_cast<size_t>(rawPtr) + rawSize;
				if (end > fileSize) {
					LogError(L"[BunVFS/Verify] FAIL: Section[%u] '%.8S' extends beyond file: "
						L"RawPtr=0x%lX + RawSize=0x%lX = 0x%llX > fileSize=0x%llX",
						s, secName, rawPtr, rawSize, (unsigned long long)end, (unsigned long long)fileSize);
					valid = false;
					goto done;
				}
			}
		}

		// 4) Check export directory and verify expected symbols
		if (checkExports) {
			int exportCount = 0;
			bool hasSetLogCallback = PEDllExportsSymbol(base, fileSize, "setLogCallback", &exportCount);

			if (exportCount == 0) {
				LogWarn(L"[BunVFS/Verify] WARNING: DLL has NO exports at all - likely wrong PE or truncated!");
				valid = false;
				goto done;
			}

			if (!hasSetLogCallback) {
				LogError(L"[BunVFS/Verify] FAIL: Required symbol 'setLogCallback' not found in exports.");
				LogError(L"[BunVFS/Verify]   This PE DLL is likely the wrong embedded image.");
				valid = false;
				goto done;
			}
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
			DWORD certOff = *reinterpret_cast<const DWORD*>(base + ddOff + 4 * 8);
			DWORD certSize = *reinterpret_cast<const DWORD*>(base + ddOff + 4 * 8 + 4);
			if (certOff > 0 && certSize > 0) {
				size_t certEnd = static_cast<size_t>(certOff) + certSize;
				if (certEnd > fileSize) {
					LogError(L"[BunVFS/Verify] FAIL: Certificate data extends beyond file");
					valid = false;
					goto done;
				}
			}
		}
	}

done:
	UnmapViewOfFile(base);
	CloseHandle(hMap);
	CloseHandle(hFile);

	if (valid) {}
	else {
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

	DWORD scanStartTick = GetTickCount();

	for (size_t off = scanStart; off + 0x200 < fileSize; ++off) {
		if (base[off] != 'M' || base[off + 1] != 'Z') continue;

		++mzCandidates;

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

		// Skip past this PE image to avoid finding sub-images
		if (peSize > 0x200) {
			off += peSize - 1;  // -1 because the for loop will ++off
		}
	}

	DWORD scanElapsed = GetTickCount() - scanStartTick;

	if (candidates.empty()) {
		LogWarn(L"[BunVFS/Extract] No valid PE DLL found in exe. DLL may be compressed/encrypted.");
		UnmapViewOfFile(base);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return false;
	}

	// Phase 2: Select best candidate
	// Priority: candidates with "setLogCallback" export, then largest by export count

	const PECandidate* best = nullptr;
	for (const auto& c : candidates) {

		if (!best) {
			best = &c;
		}
		else if (c.hasTargetExport && !best->hasTargetExport) {
			// Prefer candidate with the target export
			best = &c;
		}
		else if (c.hasTargetExport == best->hasTargetExport) {
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

	if (!best->hasTargetExport) {
		LogWarn(L"[BunVFS/Extract] WARNING: No candidate has 'setLogCallback' export! "
			L"Extracting best available, but LoadLibrary/GetProcAddress may still fail.");
	}

	// Phase 3: Extract selected candidate to disk
	std::wstring name = dllName.empty() ? L"opentui.dll" : dllName;
	outPath = outDir;
	if (!outPath.empty() && outPath.back() != L'\\') outPath += L'\\';
	outPath += name;

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

			// Final verification on the extracted file
			if (VerifyExtractedDll(outPath, true)) {
				found = true;
			}
			else {
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
						}
						else {
							LogError(L"[BunVFS/Extract] Expanded extraction also FAILED. Deleting.");
							DeleteFileW(outPath.c_str());
						}
					}
				}
				else {
					DeleteFileW(outPath.c_str());
				}
			}
		}
	}
	else {
		LogError(L"[BunVFS/Extract] Failed to create output file: %ls (err=%lu)", outPath.c_str(), GetLastError());
	}

	UnmapViewOfFile(base);
	CloseHandle(hMap);
	CloseHandle(hFile);

	if (!found) {
		LogError(L"[BunVFS/Extract] DLL extraction FAILED. OpenCode may not start correctly.");
	}
	return found;
}

// Resolve absolute path of the exe
static std::wstring ResolveExeFullPath(PCWSTR exeName) {
	if (!exeName) return L"";
	std::wstring image = ParseImagePathFromCommandLine(exeName);
	if (image.empty()) return L"";

	if (image.find(L'\\') != std::wstring::npos || image.find(L'/') != std::wstring::npos) {
		DWORD attrs = GetFileAttributesW(image.c_str());
		if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
			return image;
		}
		return L"";
	}

	std::wstring exeDir = GetExeDir();
	if (!exeDir.empty()) {
		std::wstring c = JoinPath(exeDir, image);
		DWORD a = GetFileAttributesW(c.c_str());
		if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
			return c;
		}
	}

	for (const auto& entry : AllowedPaths) {
		std::wstring c = JoinPath(entry.path, image);
		DWORD a = GetFileAttributesW(c.c_str());
		if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
			return c;
		}
	}

	wchar_t fullPath[MAX_PATH * 2] = {};
	DWORD n = SearchPathW(nullptr, image.c_str(), L".exe", _countof(fullPath), fullPath, nullptr);
	if (n > 0 && n < _countof(fullPath)) {
		return std::wstring(fullPath, n);
	}

	LogWarn(L"[BunVFS/Resolve] Could not resolve exe path for: %ls", image.c_str());
	return L"";
}

// Create B:\~BUN\root\ on disk, extract embedded DLL, and map B: drive
static bool PrepareBunVirtualDrive(PSID appContainerSid) {
	if (!ExeToLaunch) {
		return false;
	}

	std::wstring image = ParseImagePathFromCommandLine(ExeToLaunch);
	std::wstring nameLower = ToLowerCopy(GetFileNamePart(image));

	if (nameLower.find(L"opencode") == std::wstring::npos) {
		return false;
	}

	// Check if B: is already in use (e.g. a real fixed drive on the system).
	// If so, we CANNOT map our staging dir to B:, but we MUST still extract
	// the DLL and set up fallback paths (PATH prepend)
	// so the child process can find the opentui DLL.
	UINT driveType = GetDriveTypeW(L"B:\\");
	bool bDriveAvailable = (driveType == DRIVE_NO_ROOT_DIR || driveType == 0);
	if (!bDriveAvailable) {
		LogWarn(L"[BunVFS] B: drive already exists (type=%u). Will skip B: mapping but still extract DLL for fallback paths.", driveType);
	}

	std::wstring exeFullPath = ResolveExeFullPath(ExeToLaunch);
	if (exeFullPath.empty()) {
		LogWarn(L"[BunVFS] Cannot locate exe file for DLL extraction.");
		return false;
	}

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
		}
	}

	std::wstring stagingBase = AllowedPaths.empty() ? GetExeDir() : AllowedPaths[0].path;
	if (stagingBase.empty()) {
		LogWarn(L"[BunVFS] No suitable base directory for staging.");
		return false;
	}

	g_BunStagingDir = JoinPath(stagingBase, L".bun-vfs");
	std::wstring bunDir = JoinPath(g_BunStagingDir, L"~BUN");
	std::wstring dllDir = JoinPath(bunDir, L"root");

	CreateDirectoryW(g_BunStagingDir.c_str(), nullptr);
	CreateDirectoryW(bunDir.c_str(), nullptr);
	CreateDirectoryW(dllDir.c_str(), nullptr);

	if (!DirectoryExists(dllDir)) {
		LogError(L"[BunVFS] Failed to create DLL directory: %ls", dllDir.c_str());
		return false;
	}

	// Find expected DLL name from binary
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

	if (!dllName.empty()) {}
	else {
		LogWarn(L"[BunVFS] Could not find DLL name pattern in exe.");
	}

	// Check if already extracted and still valid (including export check)
	bool alreadyExtracted = false;
	std::wstring dllPath;
	if (!dllName.empty()) {
		dllPath = JoinPath(dllDir, dllName);
		DWORD a = GetFileAttributesW(dllPath.c_str());
		if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
			if (VerifyExtractedDll(dllPath, true)) {
				alreadyExtracted = true;
			}
			else {
				LogWarn(L"[BunVFS] Existing DLL FAILED verification! Deleting and re-extracting.");
				DeleteFileW(dllPath.c_str());
			}
		}
	}

	if (!alreadyExtracted) {
		std::wstring extractedPath;
		if (ExtractEmbeddedDllFromExe(exeFullPath, dllDir, dllName, extractedPath)) {
			dllPath = extractedPath;
		}
		else {
			LogWarn(L"[BunVFS] Could not extract DLL. Mapping B: anyway for Bun's own attempt.");
		}
	}

	// === DLL Fallback Mechanism ===
	// Even if B: mapping works, AppContainer namespace isolation may make it
	// invisible to the child. Set up fallback paths that always work:

	// Fallback 1: Add DLL staging directory to PATH prepend
	// This allows LoadLibrary("opentui-xxx.dll") to find it via PATH search.
	if (!dllDir.empty() && DirectoryExists(dllDir)) {
		if (AddPathPrependUnique(dllDir)) {}
	}

	// Grant AppContainer full access
	if (appContainerSid) {
		DWORD dw = GrantFullControlToSidOnPath(g_BunStagingDir.c_str(), appContainerSid);
		if (dw == ERROR_SUCCESS) {}
		else {
			LogWarn(L"[BunVFS] Grant (F) failed: %ls (err=%lu)", g_BunStagingDir.c_str(), dw);
		}
	}

	// Map B: -> staging dir (only if B: is not already in use)
	if (bDriveAvailable) {
		if (DefineDosDeviceW(0, L"B:", g_BunStagingDir.c_str())) {
			g_BunDriveMapped = true;
			g_BunDriveTarget = g_BunStagingDir;
			LogWarn(L"[BunVFS] Note: B: mapping may not be visible inside AppContainer due to namespace isolation.");
		}
		else {
			DWORD err = GetLastError();
			LogWarn(L"[BunVFS] DefineDosDeviceW failed (err=%lu) - non-fatal, fallback paths available.", err);
		}
	}

	// Verify B: mapping if we created one
	if (g_BunDriveMapped) {
		if (DirectoryExists(L"B:\\~BUN\\root")) {}
		else {
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
				++fileCount;
			} while (FindNextFileW(hFind, &fd));
			FindClose(hFind);
		}
	}

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
		if (!AllowedPaths.empty() && !AllowedPaths[0].path.empty()) {
			bool dup = false;
			for (int i = 0; i < numCandidates; ++i) {
				if (IEquals(AllowedPaths[0].path, candidateBases[i])) { dup = true; break; }
			}
			if (!dup) candidateBases[numCandidates++] = AllowedPaths[0].path;
		}

		for (int i = 0; i < numCandidates; ++i) {
			std::wstring bunFallbackBase = JoinPath(candidateBases[i], L".bun");
			std::wstring bunFallbackBun = JoinPath(bunFallbackBase, L"~BUN");
			std::wstring bunFallbackRoot = JoinPath(bunFallbackBun, L"root");
			std::wstring bunFallbackDll = JoinPath(bunFallbackRoot, dllFileName);

			CreateDirectoryW(bunFallbackBase.c_str(), nullptr);
			CreateDirectoryW(bunFallbackBun.c_str(), nullptr);
			CreateDirectoryW(bunFallbackRoot.c_str(), nullptr);

			if (DirectoryExists(bunFallbackRoot)) {
				// Copy DLL to fallback location (overwrite if exists)
				if (CopyFileW(dllPath.c_str(), bunFallbackDll.c_str(), FALSE)) {
					g_BunFallbackDirs.push_back(bunFallbackBase);

					// Add to PATH prepend
					if (AddPathPrependUnique(bunFallbackRoot)) {}

					// Grant AppContainer access to the .bun tree
					if (appContainerSid) {
						GrantFullControlToSidOnPath(bunFallbackBase.c_str(), appContainerSid);
					}

					// Add to allowed paths for ACL
					AddAllowedPathUnique(bunFallbackBase);
				}
				else {
					DWORD copyErr = GetLastError();
					LogWarn(L"[BunVFS]   Fallback 2[%d]: CopyFile to %ls failed (err=%lu)", i, bunFallbackDll.c_str(), copyErr);
				}
			}
			else {
				LogWarn(L"[BunVFS]   Fallback 2[%d]: Could not create directory: %ls", i, bunFallbackRoot.c_str());
			}
		}

	}

	return true;
}

// Thread-safe cleanup: remove B: drive mapping
static void CleanupBunVirtualDrive() {
	if (InterlockedCompareExchange(&g_BunCleanupDone, 1, 0) != 0) {
		return;
	}

	// Step 1: Remove B: drive mapping (if active)
	if (g_BunDriveMapped) {

		if (DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
			L"B:", g_BunDriveTarget.c_str())) {
		}
		else {
			DWORD err = GetLastError();
			LogWarn(L"[BunVFS/Cleanup] Failed to remove B: mapping (err=%lu). May need: subst B: /d", err);
		}

		UINT driveType = GetDriveTypeW(L"B:\\");
		if (driveType == DRIVE_NO_ROOT_DIR || driveType == 0) {}
		else {
			LogWarn(L"[BunVFS/Cleanup] B: still exists (type=%u)!", driveType);
		}

		g_BunDriveMapped = false;
	}

	// Step 2: Delete staging directory (.bun-vfs)
	if (!g_BunStagingDir.empty() && DirectoryExists(g_BunStagingDir)) {
		DWORD dw = DeleteTreeNoFollow(g_BunStagingDir);
		if (dw == ERROR_SUCCESS) {}
		else {
			LogWarn(L"[BunVFS/Cleanup] Failed to delete staging directory: %ls (err=%lu)", g_BunStagingDir.c_str(), dw);
		}
	}

	// Step 3: Delete .bun fallback directories
	for (const auto& fbDir : g_BunFallbackDirs) {
		if (!fbDir.empty() && DirectoryExists(fbDir)) {
			DWORD dw = DeleteTreeNoFollow(fbDir);
			if (dw == ERROR_SUCCESS) {}
			else {
				LogWarn(L"[BunVFS/Cleanup] Failed to delete fallback: %ls (err=%lu)", fbDir.c_str(), dw);
			}
		}
	}
	g_BunFallbackDirs.clear();
}

static void AtExitCleanupBunDrive() {
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
		return false;
	}

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
	}
	else {
		LogWarn(L"[Env] GetEnvironmentStringsW failed: err=%lu", GetLastError());
	}

	for (const auto& ov : EnvOverrides) {
		if (ov.name.empty() || ov.name.find(L'=') != std::wstring::npos) continue;
		bool replaced = false;
		for (auto& cur : vars) {
			if (IEquals(cur.name, ov.name)) {
				cur.value = ov.value;
				replaced = true;
				break;
			}
		}
		if (!replaced) {
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
			}
			else if (it->value.empty()) {
				it->value = prependJoined;
			}
			else {
				it->value = prependJoined + L";" + it->value;
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

	return true;
}

// ========================================================================
// Process Launcher (Restricted Token mode - allows child processes)
// ========================================================================

// 从令牌中提取 Logon SID（用于进程隔离：设置 Default DACL 和文件 ACL）
// 返回的 SID 需要调用方 LocalFree()
static PSID GetLogonSidFromToken(HANDLE hToken) {
	DWORD len = 0;
	GetTokenInformation(hToken, TokenLogonSid, nullptr, 0, &len);
	if (len == 0) {
		// 回退：尝试从 TokenGroups 中找 SE_GROUP_LOGON_ID
		GetTokenInformation(hToken, TokenGroups, nullptr, 0, &len);
		if (len == 0) return nullptr;
		PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, len);
		if (!pGroups) return nullptr;
		if (!GetTokenInformation(hToken, TokenGroups, pGroups, len, &len)) {
			LocalFree(pGroups);
			return nullptr;
		}
		PSID result = nullptr;
		for (DWORD i = 0; i < pGroups->GroupCount; ++i) {
			if ((pGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
				DWORD sidLen = GetLengthSid(pGroups->Groups[i].Sid);
				result = (PSID)LocalAlloc(LPTR, sidLen);
				if (result) CopySid(sidLen, result, pGroups->Groups[i].Sid);
				break;
			}
		}
		LocalFree(pGroups);
		return result;
	}
	PTOKEN_GROUPS pLogon = (PTOKEN_GROUPS)LocalAlloc(LPTR, len);
	if (!pLogon) return nullptr;
	if (!GetTokenInformation(hToken, TokenLogonSid, pLogon, len, &len) || pLogon->GroupCount == 0) {
		LocalFree(pLogon);
		return nullptr;
	}
	DWORD sidLen = GetLengthSid(pLogon->Groups[0].Sid);
	PSID result = (PSID)LocalAlloc(LPTR, sidLen);
	if (result) CopySid(sidLen, result, pLogon->Groups[0].Sid);
	LocalFree(pLogon);
	return result;
}

// 创建带 KILL_ON_JOB_CLOSE 的 Job Object，确保子进程树不会残留
static HANDLE CreateKillOnCloseJob() {
	HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
	if (!hJob) {
		LogWarn(L"[Job] CreateJobObjectW failed: err=%lu", GetLastError());
		return nullptr;
	}
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
	jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
		&jeli, sizeof(jeli))) {
		LogWarn(L"[Job] SetInformationJobObject failed: err=%lu", GetLastError());
		CloseHandle(hJob);
		return nullptr;
	}
	LogInfo(L"[Job] Created Job Object with KILL_ON_JOB_CLOSE (handle=%p)", hJob);

	// ★ UI 隔离：阻止沙箱进程使用 Job 外进程的 USER 句柄
	JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrict = {};
	uiRestrict.UIRestrictionsClass =
		JOB_OBJECT_UILIMIT_HANDLES |           // 禁止使用 Job 外进程的 USER 句柄
		JOB_OBJECT_UILIMIT_GLOBALATOMS |       // 隔离全局原子表
		JOB_OBJECT_UILIMIT_DESKTOP |           // 禁止创建/切换桌面
		JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;   // 禁止修改系统参数
	if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions,
		&uiRestrict, sizeof(uiRestrict))) {
		LogWarn(L"[Job] UI restrictions failed: err=%lu (non-fatal)", GetLastError());
	}
	else {
		LogInfo(L"[Job] UI restrictions applied (HANDLES|GLOBALATOMS|DESKTOP|SYSTEMPARAMS)");
	}

	return hJob;
}

static std::vector<DWORD> SnapshotConsoleHostPids() {
	std::vector<DWORD> pids;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return pids;

	PROCESSENTRY32W pe{};
	pe.dwSize = sizeof(pe);
	if (Process32FirstW(hSnap, &pe)) {
		do {
			std::wstring name = ToLowerCopy(pe.szExeFile);
			if (name == L"openconsole.exe" || name == L"conhost.exe") {
				pids.push_back(pe.th32ProcessID);
			}
		} while (Process32NextW(hSnap, &pe));
	}
	CloseHandle(hSnap);
	return pids;
}

static DWORD FindNewConsoleHostPid(const std::vector<DWORD>& before) {
	g_ConsoleHostsToCleanup.clear();
	// 等待控制台宿主创建完成
	// Windows Terminal 需要一些时间来启动 OpenConsole.exe
	int stableRoundsAfterFound = 0;
	for (int attempt = 0; attempt < 10; attempt++) {
		Sleep(200);
		auto after = SnapshotConsoleHostPids();

		bool addedThisRound = false;
		for (DWORD pid : after) {
			bool isNew = true;
			for (DWORD oldPid : before) {
				if (pid == oldPid) { isNew = false; break; }
			}
			if (!isNew) continue;

			if (std::find(g_ConsoleHostsToCleanup.begin(), g_ConsoleHostsToCleanup.end(), pid) != g_ConsoleHostsToCleanup.end()) {
				continue;
			}

			g_ConsoleHostsToCleanup.push_back(pid);
			addedThisRound = true;
			LogInfo(L"[Console] New console host detected: PID=%lu (attempt %d)", pid, attempt + 1);
		}
		if (!g_ConsoleHostsToCleanup.empty()) {
// 再给几轮机会抓“稍晚出现”的 host（避免只抓到 1 个）
			stableRoundsAfterFound = addedThisRound ? 0 : (stableRoundsAfterFound + 1);
			if (stableRoundsAfterFound >= 2) break; // 连续两轮没有新增（约 400ms）就认为稳定
			continue;
		}
		if (attempt == 0) {
			LogInfo(L"[Console] Waiting for console host to appear...");
		}
	}

	if (g_ConsoleHostsToCleanup.empty()) {
		LogWarn(L"[Console] No new console host found after 10 attempts");
		return 0;
	}
	return g_ConsoleHostsToCleanup.front();
}

// ========================================================================
// 终止残留的控制台宿主进程（Job 关闭后调用）
// 先等待一小段时间让它自行退出，超时则强制终止。
// ========================================================================
static void TerminateConsoleHostPid(DWORD pid, PCWSTR tag, DWORD gracefulWaitMs) {
	if (pid == 0) return;

	// 先用 querysync 打开（更容易成功）
	HANDLE hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
	if (!hQuery) {
		DWORD err = GetLastError();
		if (err == ERROR_INVALID_PARAMETER) {
			LogInfo(L"[Console] %ls console host already exited: PID=%lu", tag, pid);
		}
		else {
			LogWarn(L"[Console] %ls OpenProcess(query) failed: PID=%lu err=%lu", tag, pid, err);
		}
		return;
	}

	// 给它一个“自行退出”的窗口（OpenConsole 有时会延迟退出）
	DWORD wr = WaitForSingleObject(hQuery, gracefulWaitMs);
	CloseHandle(hQuery);

	if (wr == WAIT_OBJECT_0) {
		LogInfo(L"[Console] %ls console host exited: PID=%lu", tag, pid);
		return;
	}

	// 还活着，再尝试 terminate
	HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (!hTerm) {
		DWORD err = GetLastError();
		if (err == ERROR_INVALID_PARAMETER) {
			LogInfo(L"[Console] %ls console host already exited: PID=%lu", tag, pid);
		}
		else {
			LogWarn(L"[Console] %ls OpenProcess(terminate) failed: PID=%lu err=%lu", tag, pid, err);
		}
		return;
	}

	if (TerminateProcess(hTerm, 0)) {
		LogInfo(L"[Console] %ls terminated console host: PID=%lu", tag, pid);
	}
	else {
		DWORD err = GetLastError();
		LogWarn(L"[Console] %ls TerminateProcess failed: PID=%lu err=%lu", tag, pid, err);
	}
	CloseHandle(hTerm);
}

static void TerminateConsoleHostIfAlive() {
	if (!g_ConsoleHostsToCleanup.empty()) {
		for (DWORD pid : g_ConsoleHostsToCleanup) {
			TerminateConsoleHostPid(pid, L"Child", 5000);
		}
		g_ConsoleHostsToCleanup.clear();
	}
	else {
		TerminateConsoleHostPid(g_ChildConsoleHostPid, L"Child", 5000);
	}
	g_ChildConsoleHostPid = 0;
}

static void TerminateParentConsoleHostIfAlive() {
	TerminateConsoleHostPid(g_ParentConsoleHostPid, L"Parent", 2000);
	g_ParentConsoleHostPid = 0;
}


static void AssignProcessToJob(HANDLE hJob, HANDLE hProcess) {
	if (!hJob || !hProcess) {
		LogWarn(L"[Job] AssignProcessToJob skipped: hJob=%p, hProcess=%p", hJob, hProcess);
		return;
	}
	if (!AssignProcessToJobObject(hJob, hProcess)) {
		LogWarn(L"[Job] AssignProcessToJobObject failed: err=%lu", GetLastError());
	}
	else {
		LogInfo(L"[Job] Process assigned to Job Object successfully");
	}
}


static DWORD LaunchProcessWithRestrictedToken() {
	DWORD result = ERROR_SUCCESS;
	LogInfo(L"[Launch] Starting with Restricted Token: %ls (wait=%ls, newConsole=%ls)",
		ExeToLaunch, WaitForExit ? L"yes" : L"no", UseNewConsole ? L"yes" : L"no");

	SAFER_LEVEL_HANDLE hLevel = NULL;
	HANDLE hRestrictedToken = NULL;

	do {
		// 创建 Job Object（全局保存，OnConsoleCtrl / atexit 也可关闭）
		if (!g_hJob) {
			g_hJob = CreateKillOnCloseJob();
		}
		if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &hLevel, NULL)) {
			result = GetLastError();
			LogError(L"[Launch] SaferCreateLevel failed: err=%lu", result);
			break;
		}

		if (!SaferComputeTokenFromLevel(hLevel, NULL, &hRestrictedToken, 0, NULL)) {
			result = GetLastError();
			LogError(L"[Launch] SaferComputeTokenFromLevel failed: err=%lu", result);
			SaferCloseLevel(hLevel);
			break;
		}
		SaferCloseLevel(hLevel);
		hLevel = NULL;

		// ★ 进程隔离（Restricted Token 模式）：
		//   - Default DACL = logon SID + SYSTEM → 沙箱创建的子进程/对象外部无法访问
		//   - Job Object UI 限制 → USER 句柄隔离
		//   - 低完整性级别 → 阻止对外部中/高完整性进程的写操作（Terminate/Inject）
		//   注意：restricted SIDs 方案已移除，因为它影响所有访问检查（文件/DLL/注册表），
		//   导致 CreateProcessAsUserW 失败。完整的进程读隔离请使用 AppContainer 模式。
		{
			PSID pLogonSid = GetLogonSidFromToken(hRestrictedToken);

			// ★ 设置 Default DACL：包含 logon SID，让沙箱内进程可以互相访问
			if (pLogonSid) {
				DWORD aclSize = sizeof(ACL)
					+ 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD))
					+ GetLengthSid(pLogonSid);
				// 也给 SYSTEM 访问权
				PSID pSystem = nullptr;
				SID_IDENTIFIER_AUTHORITY ntAuth2 = SECURITY_NT_AUTHORITY;
				AllocateAndInitializeSid(&ntAuth2, 1, SECURITY_LOCAL_SYSTEM_RID,
					0, 0, 0, 0, 0, 0, 0, &pSystem);
				if (pSystem) aclSize += sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(pSystem);

				PACL pAcl = (PACL)LocalAlloc(LPTR, aclSize);
				if (pAcl && InitializeAcl(pAcl, aclSize, ACL_REVISION)) {
					AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, pLogonSid);
					if (pSystem) AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, pSystem);

					TOKEN_DEFAULT_DACL tdd = {};
					tdd.DefaultDacl = pAcl;
					if (SetTokenInformation(hRestrictedToken, TokenDefaultDacl, &tdd, sizeof(tdd))) {
						LogInfo(L"[Launch] Default DACL set with logon SID + SYSTEM");
					}
					else {
						LogWarn(L"[Launch] SetTokenInformation(DefaultDacl) failed: err=%lu", GetLastError());
					}
				}
				if (pAcl) LocalFree(pAcl);
				if (pSystem) FreeSid(pSystem);
			}

			if (pLogonSid) LocalFree(pLogonSid);
		}

		TOKEN_MANDATORY_LABEL tml = { 0 };
		tml.Label.Attributes = SE_GROUP_INTEGRITY;

		const wchar_t* integritySid = L"S-1-16-4096";  // Low
		const wchar_t* integrityName = L"Low";
		if (IntegrityLevel == 1) {
			integritySid = L"S-1-16-8192";  // Medium
			integrityName = L"Medium";
		}
		else if (IntegrityLevel == 2) {
			integritySid = L"S-1-16-12288";  // High
			integrityName = L"High";
		}

		if (!ConvertStringSidToSid((LPWSTR)integritySid, &tml.Label.Sid)) {
			result = GetLastError();
			LogError(L"[Launch] ConvertStringSidToSid failed: err=%lu", result);
			CloseHandle(hRestrictedToken);
			break;
		}

		DWORD tmlSize = sizeof(tml) + GetLengthSid(tml.Label.Sid);
		if (!SetTokenInformation(hRestrictedToken, TokenIntegrityLevel, &tml, tmlSize)) {
			result = GetLastError();
			LogError(L"[Launch] SetTokenInformation(TokenIntegrityLevel) failed: err=%lu", result);
			LocalFree(tml.Label.Sid);
			CloseHandle(hRestrictedToken);
			break;
		}
		LocalFree(tml.Label.Sid);

		LogInfo(L"[Launch] Restricted token created with %ls integrity level", integrityName);

		STARTUPINFOEXW si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		si.StartupInfo.cb = sizeof(si);

		DWORD createFlags = 0;
		LPVOID envBlock = nullptr;
		if (!g_ChildEnv.empty()) {
			envBlock = g_ChildEnv.data();
			createFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
		if (UseNewConsole) {
			createFlags |= CREATE_NEW_CONSOLE;
		}
		std::vector<DWORD> consoleHostsBefore;
		if (UseNewConsole) {
			consoleHostsBefore = SnapshotConsoleHostPids();
		}
		createFlags |= CREATE_SUSPENDED;
		// CreateProcessWithTokenW 只需 SeImpersonatePrivilege（普通管理员默认有），
		// 而 CreateProcessAsUserW 需要 SeAssignPrimaryTokenPrivilege（仅服务账户有）。
		BOOL launched = CreateProcessWithTokenW(hRestrictedToken, 0,
			NULL, ExeToLaunch, createFlags, envBlock, NULL, &si.StartupInfo, &pi);
		if (!launched) {
			result = GetLastError();
			LogWarn(L"[Launch] CreateProcessWithTokenW failed: err=%lu, trying CreateProcessAsUserW...", result);
			// 回退到 CreateProcessAsUserW
			launched = CreateProcessAsUserW(hRestrictedToken, NULL, ExeToLaunch, NULL, NULL, FALSE,
				createFlags, envBlock, NULL, &si.StartupInfo, &pi);
			if (!launched) {
				result = GetLastError();
				LogError(L"[Launch] CreateProcessAsUserW FAILED: err=%lu", result);
				if (result == ERROR_ACCESS_DENIED)
					LogError(L"[Launch] Hint: ACCESS_DENIED - check if the exe is accessible.");
				else if (result == ERROR_FILE_NOT_FOUND)
					LogError(L"[Launch] Hint: FILE_NOT_FOUND - verify the exe path is correct.");
				else if (result == ERROR_PRIVILEGE_NOT_HELD)
					LogError(L"[Launch] Hint: PRIVILEGE_NOT_HELD - need SeAssignPrimaryTokenPrivilege or SeImpersonatePrivilege.");
				CloseHandle(hRestrictedToken);
				break;
			}
		}

		AssignProcessToJob(g_hJob, pi.hProcess);
		g_ChildProcess = pi.hProcess;
		CloseHandle(hRestrictedToken);
		ResumeThread(pi.hThread);
		LogInfo(L"[Launch] Process created: PID=%lu, TID=%lu", pi.dwProcessId, pi.dwThreadId);

		// 先隐藏父控制台
		if (HideParentConsole && UseNewConsole && WaitForExit) {
			DWORD pids[16] = {};
			DWORD procCount = GetConsoleProcessList(pids, 16);
			if (procCount <= 1) {
				HWND hwnd = GetConsoleWindow();
				if (hwnd) {
					DWORD consolePid = 0;
					GetWindowThreadProcessId(hwnd, &consolePid);

					// Win11  Windows Terminal: hiding GetConsoleWindow() may only minimize.
					// Workaround: focus it, then hide the real foreground top-level window (same owner PID).
					HWND hideHwnd = hwnd;
					SetForegroundWindow(hwnd);
					HWND fg = GetForegroundWindow();
					if (fg) {
						DWORD fgPid = 0;
						GetWindowThreadProcessId(fg, &fgPid);
						if (fgPid == consolePid) {
							hideHwnd = fg;
						}
					}
					ShowWindow(hideHwnd, SW_HIDE);

					// Only treat it as "console host" if it looks like one (openconsole/conhost)
					// so we don't accidentally terminate WindowsTerminal.exe or other UI process.
					if (consolePid != 0 && consolePid != GetCurrentProcessId()) {
						bool isKnownHost = false;
						for (DWORD pid : consoleHostsBefore) {
							if (pid == consolePid) { isKnownHost = true; break; }
						}
						if (isKnownHost) {
							g_ParentConsoleHostPid = consolePid;
							LogInfo(L"[Console] Parent console host: PID=%lu", consolePid);
						}
						else {
							LogWarn(L"[Console] Parent console PID=%lu not in SnapshotConsoleHostPids(); skip cleanup", consolePid);
						}
					}
				}
			}
		}

		// ★ diff 找出新增的控制台宿主
		if (UseNewConsole && g_hJob) {
			g_ChildConsoleHostPid = FindNewConsoleHostPid(consoleHostsBefore);
		}
		if (WaitForExit) {
			DWORD waitResult = WaitForSingleObject(pi.hProcess, INFINITE);
			if (HideParentConsole && UseNewConsole) {
				FreeConsole();
				TerminateParentConsoleHostIfAlive();
			}
			if (waitResult == WAIT_OBJECT_0) {
				DWORD exitCode = 0;
				if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
					LogInfo(L"[Launch] Child exited: code=%lu (0x%08lX)", exitCode, exitCode);
					result = exitCode;
				}
				else {
					result = GetLastError();
					LogError(L"[Launch] GetExitCodeProcess failed: err=%lu", result);
				}
			}
			else {
				result = GetLastError();
				LogError(L"[Launch] WaitForSingleObject failed: err=%lu", result);
			}
		}

		CloseHandle(pi.hThread);
		g_ChildProcess = nullptr;
		CloseHandle(pi.hProcess);

	} while (false);
	// 关闭 Job → KILL_ON_JOB_CLOSE 终止所有残留子子进程
	if (g_hJob) {
		LogInfo(L"[Launch] Closing Job Object → KILL_ON_JOB_CLOSE will terminate child tree");
		CloseHandle(g_hJob);
		g_hJob = nullptr;
	}
	TerminateConsoleHostIfAlive();
	return result;
}

// ========================================================================
// Process Launcher (AppContainer mode)
// ========================================================================
static DWORD LaunchProcess(PSID packageSid) {
	DWORD result = ERROR_SUCCESS;

	LogInfo(L"[Launch] Starting: %ls (wait=%ls, lpac=%ls, newConsole=%ls)",
		ExeToLaunch, WaitForExit ? L"yes" : L"no",
		LaunchAsLpac ? L"yes" : L"no", UseNewConsole ? L"yes" : L"no");

	bool useConPty = false;
	void* hPC = nullptr;
	HANDLE hPipeIn_R = nullptr, hPipeIn_W = nullptr;
	HANDLE hPipeOut_R = nullptr, hPipeOut_W = nullptr;
	HANDLE hRelayIn = nullptr, hRelayOut = nullptr, hStopEvent = nullptr;
	InputRelayCtx inputCtx{};
	DWORD savedInputMode = 0, savedOutputMode = 0;
	bool inputModeChanged = false, outputModeChanged = false;

	if (WaitForExit && !UseNewConsole && UseConPty && InitConPtyApi()) {
		SECURITY_ATTRIBUTES sa{};
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = TRUE;
		BOOL pipeOk = CreatePipe(&hPipeIn_R, &hPipeIn_W, &sa, 0) &&
			CreatePipe(&hPipeOut_R, &hPipeOut_W, &sa, 0);
		if (pipeOk) {
			SetHandleInformation(hPipeIn_W, HANDLE_FLAG_INHERIT, 0);
			SetHandleInformation(hPipeOut_R, HANDLE_FLAG_INHERIT, 0);
			COORD conSize = GetCurrentConsoleSize();
			HRESULT hr = g_pfnCreatePC(conSize, hPipeIn_R, hPipeOut_W, 0, &hPC);
			if (SUCCEEDED(hr)) {
				useConPty = true;
			}
			else {
				LogWarn(L"[Launch] CreatePseudoConsole failed: hr=0x%08lX", (DWORD)hr);
			}
		}
		else {
			LogWarn(L"[Launch] CreatePipe for ConPTY failed: err=%lu", GetLastError());
		}
		if (hPipeIn_R) { CloseHandle(hPipeIn_R);  hPipeIn_R = nullptr; }
		if (hPipeOut_W) { CloseHandle(hPipeOut_W); hPipeOut_W = nullptr; }
		if (!useConPty) {
			if (hPipeIn_W) { CloseHandle(hPipeIn_W);  hPipeIn_W = nullptr; }
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
		HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdin == INVALID_HANDLE_VALUE || hStdout == INVALID_HANDLE_VALUE) {
			LogWarn(L"[Launch] Cannot get console handles for raw mode (stdin=%p, stdout=%p). TUI may not work.",
				hStdin, hStdout);
		}
		if (hStdin != INVALID_HANDLE_VALUE && GetConsoleMode(hStdin, &savedInputMode)) {
			// Raw mode: ONLY VT input. Disables ENABLE_LINE_INPUT, ENABLE_ECHO_INPUT,
			// ENABLE_PROCESSED_INPUT so each keypress (including Enter) is delivered
			// immediately as a VT sequence to the child process.
			DWORD newMode = ENABLE_VIRTUAL_TERMINAL_INPUT;
			if (SetConsoleMode(hStdin, newMode)) {
				inputModeChanged = true;
			}
			else {
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
			}
			else {
				LogWarn(L"[Launch] Failed to set VT output mode: err=%lu", GetLastError());
			}
		}
	}

	DWORD attributeCount = 1;
	if (LaunchAsLpac) ++attributeCount;
	if (NoWin32k) ++attributeCount;
	if (useConPty) ++attributeCount;
	if (AllowChildProcess) ++attributeCount;

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
	bool attrListInitialized = false;
	do {
		// 创建 Job Object（当 allowChildProcess=true 时子进程可 fork，需要收割）
		if (AllowChildProcess && !g_hJob) {
			g_hJob = CreateKillOnCloseJob();
		}
		if (!InitializeProcThreadAttributeList(attrList, attributeCount, 0, &attrListSize)) {
			result = GetLastError();
			LogError(L"[Launch] InitializeProcThreadAttributeList failed: err=%lu", result);
			break;
		}
		attrListInitialized = true;
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
		}
		if (NoWin32k) {
			mitigationPolicy = PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
			if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
				&mitigationPolicy, sizeof(mitigationPolicy), nullptr, nullptr)) {
				result = GetLastError();
				LogError(L"[Launch] UpdateProcThreadAttribute(MITIGATION_POLICY) failed: err=%lu", result);
				break;
			}
		}
		if (AllowChildProcess) {
			DWORD childProcessPolicy = PROCESS_CREATION_CHILD_PROCESS_OVERRIDE;
			if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
				&childProcessPolicy, sizeof(childProcessPolicy), nullptr, nullptr)) {
				result = GetLastError();
				LogError(L"[Launch] UpdateProcThreadAttribute(CHILD_PROCESS_POLICY) failed: err=%lu", result);
				break;
			}
			LogInfo(L"[Launch] Child process policy set to OVERRIDE (allow child process creation)");
		}
		if (useConPty && hPC) {
			if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
				hPC, sizeof(hPC), nullptr, nullptr)) {
				result = GetLastError();
				LogError(L"[Launch] UpdateProcThreadAttribute(PSEUDOCONSOLE) failed: err=%lu", result);
				break;
			}
		}
		std::vector<DWORD> consoleHostsBefore;
		if (UseNewConsole && !useConPty) {
			consoleHostsBefore = SnapshotConsoleHostPids();
		}
		si.StartupInfo.cb = sizeof(si);
		si.lpAttributeList = attrList;
		DWORD createFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED;
		LPVOID envBlock = nullptr;
		if (!g_ChildEnv.empty()) { envBlock = g_ChildEnv.data(); createFlags |= CREATE_UNICODE_ENVIRONMENT; }
		if (UseNewConsole && !useConPty) createFlags |= CREATE_NEW_CONSOLE;

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

			// Clean up ConPTY resources on failure
			if (hPC) { g_pfnClosePC(hPC); hPC = nullptr; }
			if (hPipeIn_W) { CloseHandle(hPipeIn_W); hPipeIn_W = nullptr; }
			if (hPipeOut_R) { CloseHandle(hPipeOut_R); hPipeOut_R = nullptr; }
			break;
		}
		AssignProcessToJob(g_hJob, pi.hProcess);
		g_ChildProcess = pi.hProcess;  // 供 OnConsoleCtrl 使用
		ResumeThread(pi.hThread);  // 子进程现在才开始执行
		if (g_LogEnabled)wprintf(L"Successfully started AppContainer process, pid: %lu\r\n", pi.dwProcessId);
		LogInfo(L"[Launch] Process created: PID=%lu, TID=%lu", pi.dwProcessId, pi.dwThreadId);
		result = ERROR_SUCCESS;

		// Hide parent console window when child has its own console (newConsole=true).
		// Only hide if parent owns the console (double-click scenario), not if
		// launched from an existing terminal (would hide user's terminal!).
		// 先隐藏父控制台
		if (HideParentConsole && UseNewConsole && WaitForExit) {
			DWORD pids[16] = {};
			DWORD procCount = GetConsoleProcessList(pids, 16);
			if (procCount <= 1) {
				HWND hwnd = GetConsoleWindow();
				if (hwnd) {
					DWORD consolePid = 0;
					GetWindowThreadProcessId(hwnd, &consolePid);

					// Win11  Windows Terminal: hiding GetConsoleWindow() may only minimize.
					// Workaround: focus it, then hide the real foreground top-level window (same owner PID).
					HWND hideHwnd = hwnd;
					SetForegroundWindow(hwnd);
					HWND fg = GetForegroundWindow();
					if (fg) {
						DWORD fgPid = 0;
						GetWindowThreadProcessId(fg, &fgPid);
						if (fgPid == consolePid) {
							hideHwnd = fg;
						}
					}
					ShowWindow(hideHwnd, SW_HIDE);

					// Only treat it as "console host" if it looks like one (openconsole/conhost)
					// so we don't accidentally terminate WindowsTerminal.exe or other UI process.
					if (consolePid != 0 && consolePid != GetCurrentProcessId()) {
						bool isKnownHost = false;
						for (DWORD pid : consoleHostsBefore) {
							if (pid == consolePid) { isKnownHost = true; break; }
						}
						if (isKnownHost) {
							g_ParentConsoleHostPid = consolePid;
							LogInfo(L"[Console] Parent console host: PID=%lu", consolePid);
						}
						else {
							LogWarn(L"[Console] Parent console PID=%lu not in SnapshotConsoleHostPids(); skip cleanup", consolePid);
						}
					}
				}
			}
		}

		// ★ diff 找新增控制台宿主
		if (UseNewConsole && !useConPty && g_hJob) {
			g_ChildConsoleHostPid = FindNewConsoleHostPid(consoleHostsBefore);
		}

		if (useConPty) {
			HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
			HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
			if (GetConsoleMode(hStdin, &savedInputMode)) {
				SetConsoleMode(hStdin, ENABLE_VIRTUAL_TERMINAL_INPUT);
				inputModeChanged = true;
			}
			if (GetConsoleMode(hStdout, &savedOutputMode)) {
				DWORD newMode = savedOutputMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
				SetConsoleMode(hStdout, newMode);
				outputModeChanged = true;
			}
			hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			hRelayOut = CreateThread(nullptr, 0, ConPtyOutputRelay, hPipeOut_R, 0, nullptr);
			inputCtx.hPipeWrite = hPipeIn_W;
			inputCtx.hStopEvent = hStopEvent;
			hRelayIn = CreateThread(nullptr, 0, ConPtyInputRelay, &inputCtx, 0, nullptr);
		}

		if (WaitForExit) {
			DWORD waitStart = GetTickCount();
			WaitForSingleObject(pi.hProcess, INFINITE);
			if (HideParentConsole && UseNewConsole) {
				FreeConsole();
				TerminateParentConsoleHostIfAlive();
			}
			DWORD waitElapsed = GetTickCount() - waitStart;

			DWORD code = 0;
			if (GetExitCodeProcess(pi.hProcess, &code)) {
				result = code;
				LogInfo(L"[Launch] Child exited: code=%lu (0x%08lX), runtime=%lu ms",
					code, code, waitElapsed);
				// Provide hints for common error exit codes
				if (code == 0xC0000135)
					LogError(L"[Launch] STATUS_DLL_NOT_FOUND - child could not load a required DLL.");
				else if (code == 126)
					LogError(L"[Launch] ERROR_MOD_NOT_FOUND - a DLL or module failed to load.");
				else if (code == 0xC0000142)
					LogError(L"[Launch] STATUS_DLL_INIT_FAILED - DLL initialization routine failed.");
				else if (code == 5)
					LogError(L"[Launch] ERROR_ACCESS_DENIED - child was denied access to a resource.");
			}
			else {
				result = GetLastError();
				LogWarn(L"[Launch] GetExitCodeProcess failed: err=%lu, runtime=%lu ms", result, waitElapsed);
			}

			if (useConPty) {
				if (hStopEvent) SetEvent(hStopEvent);
				if (hPC) { g_pfnClosePC(hPC); hPC = nullptr; }
				if (hRelayOut) { WaitForSingleObject(hRelayOut, 5000); CloseHandle(hRelayOut); hRelayOut = nullptr; }
				if (hRelayIn) { WaitForSingleObject(hRelayIn, 2000);  CloseHandle(hRelayIn);  hRelayIn = nullptr; }
				if (hPipeIn_W) { CloseHandle(hPipeIn_W);  hPipeIn_W = nullptr; }
				if (hPipeOut_R) { CloseHandle(hPipeOut_R); hPipeOut_R = nullptr; }
				if (hStopEvent) { CloseHandle(hStopEvent); hStopEvent = nullptr; }
				if (inputModeChanged) {
					SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), savedInputMode);
				}
				if (outputModeChanged) {
					SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), savedOutputMode);
				}
			}
			else if (inputModeChanged || outputModeChanged) {
				// Restore shared console VT mode
				if (inputModeChanged) {
					SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), savedInputMode);
				}
				if (outputModeChanged) {
					SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), savedOutputMode);
				}
			}
		}

		if (pi.hThread) CloseHandle(pi.hThread);
		if (pi.hProcess) {
			g_ChildProcess = nullptr;
			CloseHandle(pi.hProcess);
		}
	} while (false);
	if (g_hJob) {
		LogInfo(L"[Launch] Closing Job Object → KILL_ON_JOB_CLOSE will terminate child tree");
		CloseHandle(g_hJob);
		g_hJob = nullptr;
	}
	// ★ 终止残留控制台宿主
	TerminateConsoleHostIfAlive();
	if (attrList) {
		if (attrListInitialized) DeleteProcThreadAttributeList(attrList);
		HeapFree(GetProcessHeap(), 0, attrList);
	}
	if (inputModeChanged) {
		SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), savedInputMode);
	}
	if (outputModeChanged) {
		SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), savedOutputMode);
	}
	if (hPC) g_pfnClosePC(hPC);
	if (hPipeIn_W) CloseHandle(hPipeIn_W);
	if (hPipeOut_R) CloseHandle(hPipeOut_R);
	if (hStopEvent) CloseHandle(hStopEvent);

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
		}
		else {
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
		return false;
	}
	std::wstring dir = GetExeDir();
	if (dir.empty()) return false;
	std::wstring ini = dir + L"config.ini";
	DWORD attrs = GetFileAttributesW(ini.c_str());
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
		return false;
	}

	LogInfo(L"[Config] Loading config from: %ls", ini.c_str());
	CapabilityList.clear(); AllowedPaths.clear(); EnvOverrides.clear();
	PathPrependEntries.clear(); g_ChildEnv.clear();

	auto moniker = TrimCopy(ReadIniString(ini, L"moniker"));
	if (!moniker.empty()) { PackageMoniker = moniker; }
	auto exe = TrimCopy(ReadIniString(ini, L"exe"));
	if (!exe.empty()) {
		g_CmdLineBuf.assign(exe.begin(), exe.end());
		g_CmdLineBuf.push_back(L'\0');
		ExeToLaunch = g_CmdLineBuf.data();
	}
	auto disp = TrimCopy(ReadIniString(ini, L"displayName"));
	if (!disp.empty()) { PackageDisplayName = disp; }
	auto caps = ReadIniString(ini, L"capabilities");
	if (!caps.empty()) { ParseCapabilityListFromArg(caps.c_str()); }
	auto allowPaths = ReadIniString(ini, L"allowPaths");
	LogInfo(L"[Config] allowPaths raw: '%ls'", allowPaths.c_str());
	if (!allowPaths.empty()) { ParseAllowedPathListFromArg(allowPaths.c_str()); }
	LogInfo(L"[Config] AllowedPaths count: %llu", (unsigned long long)AllowedPaths.size());
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
	AllowChildProcess = IniBoolFromString(ReadIniString(ini, L"allowChildProcess"), AllowChildProcess);
	LogInfo(L"[Config] allowChildProcess=%s", AllowChildProcess ? L"true" : L"false");
	UseRestrictedToken = IniBoolFromString(ReadIniString(ini, L"restrictedToken"), UseRestrictedToken);
	LogInfo(L"[Config] restrictedToken=%s", UseRestrictedToken ? L"true" : L"false");

	auto integrityStr = ReadIniString(ini, L"integrityLevel");
	if (!integrityStr.empty()) {
		if (integrityStr == L"low" || integrityStr == L"0") IntegrityLevel = 0;
		else if (integrityStr == L"medium" || integrityStr == L"1") IntegrityLevel = 1;
		else if (integrityStr == L"high" || integrityStr == L"2") IntegrityLevel = 2;
	}
	LogInfo(L"[Config] integrityLevel=%d (0=Low, 1=Medium, 2=High)", IntegrityLevel);

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
		}
		else {
			LogWarn(L"[Config] Invalid networkFilterPort: %ls, using default %d",
				nfPort.c_str(), g_NetworkFilterPort);
		}
	}

	g_NetworkFilterAllowedUrls = TrimCopy(ReadIniString(ini, L"networkFilterAllowedUrls"));

	LogInfo(L"[Config] Final flags: wait=%d, retainProfile=%d, lpac=%d, noWin32k=%d, "
		L"lowIntegrityOnPaths=%d, cleanupSubdirs=%d, newConsole=%d, conpty=%d, hideParent=%d, log=%d, networkFilter=%d",
		WaitForExit ? 1 : 0, RetainProfile ? 1 : 0, LaunchAsLpac ? 1 : 0, NoWin32k ? 1 : 0,
		PathLowIntegrity ? 1 : 0, CleanupAllowedSubdirs ? 1 : 0, UseNewConsole ? 1 : 0, UseConPty ? 1 : 0, HideParentConsole ? 1 : 0, g_LogEnabled ? 1 : 0, g_NetworkFilterEnabled ? 1 : 0);
	return true;
}

// ========================================================================
// Network Filter Plugin Integration
// ========================================================================
static bool InitializeNetworkFilter() {
	if (!g_NetworkFilterEnabled) {
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
	}
}

static bool RunSilentCommand(const std::wstring& cmdLine, DWORD timeoutMs = 10000) {
	STARTUPINFOW si = {};
	PROCESS_INFORMATION pi = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
	buf.push_back(L'\0');

	if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
		LogWarn(L"[Firewall] CreateProcessW failed: err=%lu, cmd=%ls",
			GetLastError(), cmdLine.c_str());
		return false;
	}

	DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
	DWORD exitCode = 1;
	if (waitResult == WAIT_OBJECT_0) {
		GetExitCodeProcess(pi.hProcess, &exitCode);
	}
	else {
		LogWarn(L"[Firewall] Command timed out: %ls", cmdLine.c_str());
		TerminateProcess(pi.hProcess, 1);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return (exitCode == 0);
}

static void InjectProxyEnvVars() {
	if (!g_NetworkFilterEnabled || !NetworkFilterPlugin::IsRunning()) {
		return;
	}

	std::wstring proxyUrl = NetworkFilterPlugin::GetProxyUrl();

	// Set standard proxy environment variables (both cases for compatibility)
	UpsertEnvOverride(L"HTTP_PROXY", proxyUrl);
	UpsertEnvOverride(L"HTTPS_PROXY", proxyUrl);
	UpsertEnvOverride(L"http_proxy", proxyUrl);
	UpsertEnvOverride(L"https_proxy", proxyUrl);

	// Exclude localhost to prevent proxy self-loop
	UpsertEnvOverride(L"NO_PROXY", L"localhost,127.0.0.1");
	UpsertEnvOverride(L"no_proxy", L"localhost,127.0.0.1");

}

// ========================================================================
// Firewall-based Network Filter (AppContainer)
// ========================================================================

// AppContainer 加固核心：移除 internetClient (S-1-15-3-1) 和
// internetClientServer (S-1-15-3-2) 能力。
// AppContainer 没有这些能力后，子进程只能连接 loopback 地址，
// 即使子进程清除了代理环境变量也无法直连外网。
// 这是 OS 内核级别的强制隔离，不可绕过。

static void StripInternetCapabilitiesForNetworkFilter() {
	if (!g_NetworkFilterEnabled) return;

	// 定义要移除的 SID
	// S-1-15-3-1 = internetClient
	// S-1-15-3-2 = internetClientServer
	const wchar_t* sidStrings[] = { L"S-1-15-3-1", L"S-1-15-3-2" };
	PSID sidsToRemove[2] = { nullptr, nullptr };

	for (int i = 0; i < 2; ++i) {
		if (!ConvertStringSidToSidW(sidStrings[i], &sidsToRemove[i])) {
			LogWarn(L"[NetworkFilter] ConvertStringSidToSid failed for %ls: err=%lu",
				sidStrings[i], GetLastError());
		}
	}

	int removedCount = 0;
	auto it = CapabilityList.begin();
	while (it != CapabilityList.end()) {
		bool shouldRemove = false;
		for (int i = 0; i < 2; ++i) {
			if (sidsToRemove[i] && it->Sid && EqualSid(it->Sid, sidsToRemove[i])) {
				shouldRemove = true;
				break;
			}
		}

		if (shouldRemove) {
			LPWSTR sidStr = nullptr;
			ConvertSidToStringSidW(it->Sid, &sidStr);
			LogInfo(L"[NetworkFilter/Harden] Stripped internet capability: %ls "
					L"(child process can only connect to loopback)",
					sidStr ? sidStr : L"<unknown>");
			if (sidStr) LocalFree(sidStr);

			it = CapabilityList.erase(it);
			++removedCount;
		}
		else {
			++it;
		}
	}

	for (int i = 0; i < 2; ++i) {
		if (sidsToRemove[i]) LocalFree(sidsToRemove[i]);
	}

	if (removedCount > 0) {
		LogInfo(L"[NetworkFilter/Harden] Removed %d internet capabilities. "
				L"AppContainer child is now restricted to loopback-only networking.",
				removedCount);
	}
	else {
		LogInfo(L"[NetworkFilter/Harden] No internet capabilities found to remove. "
				L"AppContainer child already cannot access the network directly.");
	}
}

// Restricted Token 加固：添加 Windows 防火墙出站规则。
// 规则 1（Allow）：放行子进程到 127.0.0.1:代理端口 的 TCP 连接
// 规则 2（Block）：阻止子进程所有其他出站连接
//
// 防火墙规则按 "allow 优先于 block" 的方式工作：
// netsh 中 allow 规则如果精确匹配，会覆盖同优先级的 block 规则。
//
// 注意：需要管理员权限。如果权限不足，函数会打印警告但不会导致启动失败。

static bool AddFirewallBlockRules(const std::wstring& exePath) {
	if (!g_NetworkFilterEnabled || exePath.empty()) return false;

	g_FirewallRuleBaseName = L"OpenCodeSandbox_" + std::to_wstring(GetCurrentProcessId());

	std::wstring portStr = std::to_wstring(g_NetworkFilterPort);

	// Rule 1: Allow outbound to proxy (127.0.0.1:proxyPort)
	std::wstring allowCmd = L"netsh advfirewall firewall add rule "
		L"name=\"" + g_FirewallRuleBaseName + L"_ProxyAllow\" "
		L"dir=out action=allow protocol=tcp "
		L"remoteip=127.0.0.1 remoteport=" + portStr + L" "
		L"program=\"" + exePath + L"\" "
		L"enable=yes";

	// Rule 2: Block all other outbound from the exe
	std::wstring blockCmd = L"netsh advfirewall firewall add rule "
		L"name=\"" + g_FirewallRuleBaseName + L"_NetBlock\" "
		L"dir=out action=block protocol=any "
		L"program=\"" + exePath + L"\" "
		L"enable=yes";

	// Also block DNS (UDP 53) to prevent DNS-based exfiltration
	// (the proxy handles DNS resolution on behalf of the child)
	std::wstring dnsBlockCmd = L"netsh advfirewall firewall add rule "
		L"name=\"" + g_FirewallRuleBaseName + L"_DnsBlock\" "
		L"dir=out action=block protocol=udp "
		L"program=\"" + exePath + L"\" "
		L"enable=yes";

	// Allow rule first, then block rules
	bool ok1 = RunSilentCommand(allowCmd);
	bool ok2 = RunSilentCommand(blockCmd);
	bool ok3 = RunSilentCommand(dnsBlockCmd);

	if (ok1 && ok2) {
		g_FirewallRulesAdded = true;
		LogInfo(L"[NetworkFilter/Harden] Firewall rules added for Restricted Token mode:");
		LogInfo(L"[NetworkFilter/Harden]   ALLOW: %ls -> 127.0.0.1:%d (proxy)",
				exePath.c_str(), g_NetworkFilterPort);
		LogInfo(L"[NetworkFilter/Harden]   BLOCK: %ls -> all other outbound", exePath.c_str());
		return true;
	}
	else {
		LogWarn(L"[NetworkFilter/Harden] Failed to add firewall rules (need elevation?).");
		LogWarn(L"[NetworkFilter/Harden]   allow=%s, block=%s, dns=%s",
				ok1 ? L"ok" : L"FAIL", ok2 ? L"ok" : L"FAIL", ok3 ? L"ok" : L"FAIL");
		LogWarn(L"[NetworkFilter/Harden]   Network filter runs in SOFT mode "
				L"(env var bypass possible).");
		// Non-fatal: proxy still works, just not enforced
		return false;
	}
}

static void RemoveFirewallRules() {
	if (!g_FirewallRulesAdded || g_FirewallRuleBaseName.empty()) return;

	LogInfo(L"[NetworkFilter/Harden] Removing firewall rules...");

	std::wstring cmd1 = L"netsh advfirewall firewall delete rule "
		L"name=\"" + g_FirewallRuleBaseName + L"_ProxyAllow\"";
	std::wstring cmd2 = L"netsh advfirewall firewall delete rule "
		L"name=\"" + g_FirewallRuleBaseName + L"_NetBlock\"";
	std::wstring cmd3 = L"netsh advfirewall firewall delete rule "
		L"name=\"" + g_FirewallRuleBaseName + L"_DnsBlock\"";

	RunSilentCommand(cmd1);
	RunSilentCommand(cmd2);
	RunSilentCommand(cmd3);

	g_FirewallRulesAdded = false;
	LogInfo(L"[NetworkFilter/Harden] Firewall rules removed.");
}

// ========================================================================
// Console Control Handler
// ========================================================================
static BOOL WINAPI OnConsoleCtrl(DWORD ctrlType) {
	switch (ctrlType) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		// Ctrl+C / Ctrl+Break：通知主线程退出，主动终止子进程
		LogWarn(L"[Console] Ctrl+C/Break received. Terminating child...");
		if (g_ChildProcess) TerminateProcess(g_ChildProcess, 0xC000013A);
		return TRUE;  // 不让默认处理器终止本进程

	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		LogWarn(L"[Console] Close/logoff/shutdown (type=%lu). Cleaning up...", ctrlType);
		if (g_ChildProcess) TerminateProcess(g_ChildProcess, 0xC000013A);
		if (g_hJob) { CloseHandle(g_hJob); g_hJob = nullptr; }
		TerminateConsoleHostIfAlive();
		TerminateParentConsoleHostIfAlive();
		RemoveFirewallRules();
		ShutdownNetworkFilter();
		CleanupBunVirtualDrive();
		RestoreSavedSecurityOnce();
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
		if (g_LogEnabled)wprintf(L"[Warn] SetConsoleCtrlHandler failed: err=%lu\r\n", GetLastError());

	// Parse config and arguments FIRST to determine if logging is enabled.
	// g_LogEnabled defaults to false; set via config.ini "log=true" or CLI "-g".
	LoadConfigFromIniIfNoArgs(argc);
	if (!ParseArguments(argc, argv)) { SetConsoleCtrlHandler(OnConsoleCtrl, FALSE); return 0; }
	if (PackageMoniker.empty() || ExeToLaunch == nullptr) {
		if (g_LogEnabled)wprintf(L"[Error] Missing required parameters: moniker or exe\r\n");
		PrintUsage(); SetConsoleCtrlHandler(OnConsoleCtrl, FALSE); return 0;
	}

	// Now that g_LogEnabled is known, initialize log file and emit startup banner.
	InitLogFile();

	LogInfo(L"=== LaunchAppContainer started (PID=%lu) === Moniker=%ls, Exe=%ls, AllowedPaths=%llu",
		GetCurrentProcessId(), PackageMoniker.c_str(), ExeToLaunch,
		(unsigned long long)AllowedPaths.size());
	if (AllowedPaths.empty()) {
		wchar_t cwd[MAX_PATH] = {};
		DWORD cwdLen = GetCurrentDirectoryW(MAX_PATH, cwd);
		if (cwdLen > 0 && cwdLen < MAX_PATH) {
			AddAllowedPathUnique(std::wstring(cwd), PathAccessLevel::FullControl);
			LogInfo(L"[Config] No allowPaths configured, defaulting to current directory: %ls", cwd);
		}
		else {
			LogWarn(L"[Config] No allowPaths configured and failed to get current directory (err=%lu)", GetLastError());
		}
	}
	ResolveExePathIfSubst();
	ApplyDefaultOpenCodeEnvPaths();
	ApplyBunOpenTuiCompatibility();
	AutoEnableWaitForTuiIfNeeded();
	FixShellForAppContainer();

	if (WaitForExit) {
		UpsertEnvOverride(L"TERM", L"xterm-256color");
		UpsertEnvOverride(L"COLORTERM", L"truecolor");
	}

	if (RegSetKeyValueW(HKEY_CURRENT_USER, L"Console", L"LowBoxConsoleEnabled",
		REG_DWORD, &lowBoxConsoleEnabled, sizeof(lowBoxConsoleEnabled)) != ERROR_SUCCESS)
		LogWarn(L"[Init] Failed to set LowBoxConsoleEnabled registry key.");

	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);

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
		InitProxyLogFile();
		InjectProxyEnvVars();

		// ★ 网络过滤加固状态日志
		if (UseRestrictedToken) {
			if (g_FirewallRulesAdded) {
				LogInfo(L"[NetworkFilter] Hardening: ACTIVE (firewall rules block direct connections)");
			}
			else {
				LogWarn(L"[NetworkFilter] Hardening: INACTIVE (firewall rules failed; "
						L"child can bypass proxy by unsetting env vars)");
			}
		}
		else {
			// AppContainer mode - capabilities stripped
			LogInfo(L"[NetworkFilter] Hardening: ACTIVE (internet capabilities stripped; "
					L"OS-level loopback-only enforcement)");
		}
	}

	// ================================================================
	// Restricted Token Sandbox (allows child processes)
	// ================================================================
	if (UseRestrictedToken) {
		LogInfo(L"[Phase] Using Restricted Token mode (allows child processes)");

		HANDLE hToken = nullptr;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			DWORD tokenUserLen = 0;
			GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenUserLen);
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && tokenUserLen > 0) {
				PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, tokenUserLen);
				if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, tokenUserLen, &tokenUserLen)) {
					PSID userSid = pTokenUser->User.Sid;
					if (!AllowedPaths.empty()) {
						GrantAccessToAllowedPaths(userSid);
					}
				}
				if (pTokenUser) LocalFree(pTokenUser);
			}

			CloseHandle(hToken);
		}

		PrepareBunVirtualDrive(nullptr);
		atexit(AtExitCleanupBunDrive);
		atexit([]() { RemoveFirewallRules(); });
		SetUnhandledExceptionFilter(BunDriveCrashHandler);

		if (!EnvOverrides.empty() || !PathPrependEntries.empty()) {
			BuildChildEnvBlockFromOverrides();
		}

		LogInfo(L"[Phase] Launching child process...");
		// Restricted Token 模式：通过防火墙规则阻止子进程直连外网
		if (g_NetworkFilterEnabled && ExeToLaunch) {
			std::wstring exePath = ResolveExeFullPath(ExeToLaunch);
			if (!exePath.empty()) {
				AddFirewallBlockRules(exePath);
			}
		}
		result = LaunchProcessWithRestrictedToken();

		if (CleanupAllowedSubdirs && (WaitForExit || result != ERROR_SUCCESS)) {
			CleanupAllowedPathSubdirs();
		}

		goto Cleanup;
	}

	// ================================================================
	// AppContainer Sandbox
	// ================================================================
	// AppContainer 模式：移除 internet 能力，子进程只能通过 loopback 代理上网
	StripInternetCapabilitiesForNetworkFilter();

	LogInfo(L"[Phase] Creating AppContainer profile...");
	result = CreateAppContainerProfileWithMoniker(&appContainerSid);
	if (result != ERROR_SUCCESS) {
		LogError(L"[Phase] Failed to create AppContainer profile: err=%lu", result);
		goto Cleanup;
	}

	if (!AllowedPaths.empty()) {
		GrantAccessToAllowedPaths(appContainerSid);
	}

	// Prepare Bun virtual B: drive
	PrepareBunVirtualDrive(appContainerSid);
	atexit(AtExitCleanupBunDrive);
	atexit([]() { RemoveFirewallRules(); });
	SetUnhandledExceptionFilter(BunDriveCrashHandler);

	// Build child environment block AFTER PrepareBunVirtualDrive() so that
	// any PATH prepends and env overrides added during BunVFS setup are included.
	if (!EnvOverrides.empty() || !PathPrependEntries.empty()) {
		BuildChildEnvBlockFromOverrides();
	}

	LogInfo(L"[Phase] Launching child process...");
	result = LaunchProcess(appContainerSid);

	if (CleanupAllowedSubdirs && (WaitForExit || result != ERROR_SUCCESS)) {
		CleanupAllowedPathSubdirs();
	}

Cleanup:
	// ★ 先捕获控制台窗口句柄
	HWND consoleHwnd = GetConsoleWindow();

	// ★ 脱离控制台
	FreeConsole();

	// ★ 清理操作限时执行
	{
		HANDLE hCleanup = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
			RemoveFirewallRules();
			ShutdownNetworkFilter();
			CleanupBunVirtualDrive();
			RestoreSavedSecurityOnce();
			if (WaitForExit && !RetainProfile && g_ProfileWasCreated) {
				DeleteAppContainerProfileWithMoniker();
			}
			return 0;
		}, nullptr, 0, nullptr);
		if (hCleanup) {
			if (WaitForSingleObject(hCleanup, 8000) != WAIT_OBJECT_0) {
				LogWarn(L"[Cleanup] Timeout after 8s, forcing exit");
			}
			CloseHandle(hCleanup);
		}
	}

	if (appContainerSid) { FreeSid(appContainerSid); appContainerSid = nullptr; }
	SetConsoleCtrlHandler(OnConsoleCtrl, FALSE);

	LogInfo(L"=== LaunchAppContainer finished: result=%lu (0x%08lX) ===", result, result);
	CloseProxyLogFile();
	CloseLogFile();

	// ★ 通知 Windows Terminal 关闭此标签页
	if (consoleHwnd && IsWindow(consoleHwnd)) {
		PostMessageW(consoleHwnd, WM_CLOSE, 0, 0);
	}

	UINT exitCode = static_cast<UINT>(result);
	if (exitCode == 0xC000013A) {
		exitCode = 0;
	}
	ExitProcess(exitCode);
	return static_cast<int>(exitCode);

}