#include "NetworkFilterPlugin.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <Lmcons.h>   // for UNLEN, GetUserNameW

#undef WIN32_LEAN_AND_MEAN

#include <algorithm>
#include <cstring>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")

NetworkFilterState NetworkFilterPlugin::g_State;

// ========================================================================
// Lifecycle
// ========================================================================

bool NetworkFilterPlugin::Initialize(int port) {
	if (g_State.running) {
		LogWarn(L"[NetworkFilterPlugin] Already running, ignoring Initialize.");
		return true;
	}

	g_State.port = (port > 0 && port <= 65535) ? port : 8080;
	g_State.running = false;
	g_State.listenSocket = nullptr;
	g_State.serverThread = nullptr;

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		LogError(L"[NetworkFilterPlugin] WSAStartup failed: %d", WSAGetLastError());
		return false;
	}

	LogInfo(L"[NetworkFilterPlugin] Winsock initialized.");

	SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listenSock == INVALID_SOCKET) {
		LogError(L"[NetworkFilterPlugin] socket() failed: %d", WSAGetLastError());
		WSACleanup();
		return false;
	}

	int opt = 1;
	setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	addr.sin_port = htons(static_cast<u_short>(g_State.port));

	if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		int err = WSAGetLastError();
		LogError(L"[NetworkFilterPlugin] bind() failed on port %d: %d", g_State.port, err);
		closesocket(listenSock);
		WSACleanup();
		return false;
	}

	if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
		LogError(L"[NetworkFilterPlugin] listen() failed: %d", WSAGetLastError());
		closesocket(listenSock);
		WSACleanup();
		return false;
	}

	g_State.listenSocket = (void*)listenSock;

	g_State.serverThread = CreateThread(nullptr, 0, ProxyServerThread, nullptr, 0, nullptr);
	if (!g_State.serverThread) {
		LogError(L"[NetworkFilterPlugin] CreateThread failed: %d", GetLastError());
		closesocket(listenSock);
		WSACleanup();
		return false;
	}

	g_State.running = true;
	LogInfo(L"[NetworkFilterPlugin] Initialized and listening on 127.0.0.1:%d", g_State.port);
	LogProxyInfo(L"========== Proxy started on 127.0.0.1:%d ==========", g_State.port);
	return true;
}

void NetworkFilterPlugin::Shutdown() {
	if (!g_State.running) {
		return;
	}

	LogInfo(L"[NetworkFilterPlugin] Shutting down...");

	g_State.running = false;

	if (g_State.listenSocket != nullptr) {
		closesocket((SOCKET)g_State.listenSocket);
		g_State.listenSocket = nullptr;
	}

	if (g_State.serverThread) {
		WaitForSingleObject(g_State.serverThread, 5000);
		CloseHandle(g_State.serverThread);
		g_State.serverThread = nullptr;
	}

	// Wait for active connection threads to drain
	int waitCount = 0;
	while (g_State.activeConnections > 0 && waitCount < 50) {
		Sleep(100);
		waitCount++;
	}
	if (g_State.activeConnections > 0) {
		LogWarn(L"[NetworkFilterPlugin] %d active connections still pending after shutdown timeout",
			g_State.activeConnections.load());
	}

	WSACleanup();

	LogInfo(L"[NetworkFilterPlugin] Shutdown complete.");
	LogProxyInfo(L"========== Proxy stopped ==========");
}

void NetworkFilterPlugin::SetAllowedDomains(const std::vector<std::wstring>& domains) {
	std::lock_guard<std::mutex> lock(g_State.mutex);

	g_State.allowedDomains.clear();

	for (const auto& domain : domains) {
		DomainPattern dp;
		dp.pattern = domain;
		dp.hasWildcard = (domain.find(L'*') != std::wstring::npos);

		g_State.allowedDomains.push_back(dp);
		LogInfo(L"[NetworkFilterPlugin] Allowed domain: %ls (wildcard=%d)",
			domain.c_str(), dp.hasWildcard ? 1 : 0);
	}

	LogInfo(L"[NetworkFilterPlugin] Total %llu allowed domains configured.",
		(unsigned long long)g_State.allowedDomains.size());

	LogProxyInfo(L"--- Allowed domain rules (%llu) ---",
		(unsigned long long)g_State.allowedDomains.size());
	for (const auto& dp : g_State.allowedDomains) {
		LogProxyInfo(L"  %ls %ls", dp.hasWildcard ? L"[wildcard]" : L"  [exact]", dp.pattern.c_str());
	}
	LogProxyInfo(L"--- End of domain rules ---");
}

bool NetworkFilterPlugin::IsRunning() {
	return g_State.running;
}

int NetworkFilterPlugin::GetProxyPort() {
	return g_State.port;
}

std::wstring NetworkFilterPlugin::GetProxyUrl() {
	return L"http://127.0.0.1:" + std::to_wstring(g_State.port);
}

// ========================================================================
// Domain Matching
// ========================================================================

bool NetworkFilterPlugin::MatchDomainPattern(const std::wstring& pattern, const std::wstring& domain) {
	if (pattern.empty() || domain.empty()) {
		return false;
	}

	if (pattern == L"*") {
		return true;
	}

	size_t wildcardPos = pattern.find(L'*');

	if (wildcardPos == std::wstring::npos) {
		return _wcsicmp(pattern.c_str(), domain.c_str()) == 0;
	}

	if (wildcardPos != 0 || pattern.size() < 2) {
		LogWarn(L"[NetworkFilterPlugin] Invalid wildcard pattern: %ls", pattern.c_str());
		return false;
	}

	std::wstring suffix = pattern.substr(1); // e.g. ".anthropic.com"

	if (domain.size() < suffix.size()) {
		return false;
	}

	std::wstring domainSuffix = domain.substr(domain.size() - suffix.size());

	return _wcsicmp(suffix.c_str(), domainSuffix.c_str()) == 0;
}

// ========================================================================
// String Utilities
// ========================================================================

std::wstring NetworkFilterPlugin::StringToWide(const std::string& s) {
	if (s.empty()) return L"";
	int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
	if (size <= 0) return L"";
	std::wstring result(size - 1, 0);
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &result[0], size);
	return result;
}

std::string NetworkFilterPlugin::WideToString(const std::wstring& s) {
	if (s.empty()) return "";
	int size = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (size <= 0) return "";
	std::string result(size - 1, 0);
	WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &result[0], size, nullptr, nullptr);
	return result;
}

// ========================================================================
// LaunchApp Header
// ========================================================================

std::string NetworkFilterPlugin::GetLaunchAppHeaderValue() {
	wchar_t username[UNLEN + 1] = {};
	DWORD size = UNLEN + 1;
	if (!GetUserNameW(username, &size)) {
		LogWarn(L"[NetworkFilterPlugin] GetUserNameW failed: %d", GetLastError());
		return "unknown_opencode";
	}
	std::string u = WideToString(username);
	return u + "_opencode";
}

// ========================================================================
// HTTP Parsing
// ========================================================================

bool NetworkFilterPlugin::ParseRequestLine(const std::string& line,
	std::string& method, std::string& url, std::string& version) {
	method.clear(); url.clear(); version.clear();

	size_t pos1 = line.find(' ');
	if (pos1 == std::string::npos) return false;

	size_t pos2 = line.find(' ', pos1 + 1);
	if (pos2 == std::string::npos) return false;

	method = line.substr(0, pos1);
	url = line.substr(pos1 + 1, pos2 - pos1 - 1);
	version = line.substr(pos2 + 1);
	return true;
}

// Extract pure hostname (no port) from URL
// e.g. "http://example.com:8080/path" -> "example.com"
//      "example.com:443"             -> "example.com"
std::string NetworkFilterPlugin::ExtractHostFromUrl(const std::string& url) {
	if (url.empty()) return "";

	size_t start = 0;
	size_t protoPos = url.find("://");
	if (protoPos != std::string::npos) {
		start = protoPos + 3;
	}
	if (start >= url.size()) return "";

	// Find end of authority section (before path)
	size_t authEnd = url.find('/', start);
	if (authEnd == std::string::npos) {
		authEnd = url.size();
	}

	std::string authority = url.substr(start, authEnd - start);
	if (authority.empty()) return "";

	// Strip port from authority: "example.com:443" -> "example.com"
	// Be careful with IPv6: [::1]:443
	if (!authority.empty() && authority[0] == '[') {
		// IPv6 literal
		size_t closeBracket = authority.find(']');
		if (closeBracket != std::string::npos) {
			return authority.substr(1, closeBracket - 1);
		}
		return authority;
	}

	size_t colonPos = authority.rfind(':');
	if (colonPos != std::string::npos) {
		// Verify that everything after colon is digits (port number)
		bool isPort = true;
		for (size_t i = colonPos + 1; i < authority.size(); ++i) {
			if (!isdigit((unsigned char)authority[i])) {
				isPort = false;
				break;
			}
		}
		if (isPort && colonPos + 1 < authority.size()) {
			return authority.substr(0, colonPos);
		}
	}

	return authority;
}

// Extract host and port from URL
// e.g. "example.com:8080" -> host="example.com", port=8080
//      "http://example.com/path" -> host="example.com", port=defaultPort
void NetworkFilterPlugin::ExtractHostPortFromUrl(const std::string& url,
	std::string& outHost, int& outPort, int defaultPort) {
	outHost.clear();
	outPort = defaultPort;

	if (url.empty()) return;

	size_t start = 0;
	size_t protoPos = url.find("://");
	if (protoPos != std::string::npos) {
		// Detect default port from protocol
		std::string proto = url.substr(0, protoPos);
		for (auto& ch : proto) ch = (char)tolower((unsigned char)ch);
		if (proto == "https") defaultPort = 443;
		else if (proto == "http") defaultPort = 80;
		outPort = defaultPort;
		start = protoPos + 3;
	}
	if (start >= url.size()) return;

	// Find end of authority
	size_t authEnd = url.find('/', start);
	if (authEnd == std::string::npos) authEnd = url.size();

	std::string authority = url.substr(start, authEnd - start);
	if (authority.empty()) return;

	// Handle IPv6
	if (!authority.empty() && authority[0] == '[') {
		size_t closeBracket = authority.find(']');
		if (closeBracket != std::string::npos) {
			outHost = authority.substr(1, closeBracket - 1);
			if (closeBracket + 2 < authority.size() && authority[closeBracket + 1] == ':') {
				try {
					int p = std::stoi(authority.substr(closeBracket + 2));
					if (p > 0 && p <= 65535) outPort = p;
				}
				catch (...) {}
			}
		}
		return;
	}

	// Regular host:port
	size_t colonPos = authority.rfind(':');
	if (colonPos != std::string::npos && colonPos + 1 < authority.size()) {
		bool isPort = true;
		for (size_t i = colonPos + 1; i < authority.size(); ++i) {
			if (!isdigit((unsigned char)authority[i])) {
				isPort = false;
				break;
			}
		}
		if (isPort) {
			outHost = authority.substr(0, colonPos);
			try {
				int p = std::stoi(authority.substr(colonPos + 1));
				if (p > 0 && p <= 65535) outPort = p;
			}
			catch (...) {}
			return;
		}
	}

	outHost = authority;
}

// ========================================================================
// Socket I/O
// ========================================================================

std::string NetworkFilterPlugin::ReadLine(void* sock) {
	SOCKET s = (SOCKET)sock;
	std::string result;
	char ch;

	DWORD timeout = 30000;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

	while (true) {
		int recvResult = recv(s, &ch, 1, 0);
		if (recvResult <= 0) break;
		if (ch == '\r') continue;
		if (ch == '\n') break;
		result += ch;
		if (result.size() > 8192) break;
	}

	return result;
}

bool NetworkFilterPlugin::SendErrorResponse(void* sock, int code, const char* status, const char* body) {
	SOCKET s = (SOCKET)sock;
	// Use dynamic buffer to avoid overflow
	size_t bodyLen = strlen(body);
	size_t needed = 256 + strlen(status) + bodyLen;
	std::vector<char> response(needed);

	int len = _snprintf_s(response.data(), needed, _TRUNCATE,
		"HTTP/1.1 %d %s\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		code, status, bodyLen, body);

	if (len > 0) {
		send(s, response.data(), len, 0);
	}
	return true;
}

bool NetworkFilterPlugin::ConnectToServer(const std::string& host, int port, void*& serverSocket) {
	addrinfo hints = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	addrinfo* result = nullptr;
	int ret = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
	if (ret != 0) {
		LogError(L"[NetworkFilterPlugin] getaddrinfo failed for %hs:%d: %d", host.c_str(), port, ret);
		return false;
	}

	SOCKET serverSock = INVALID_SOCKET;
	for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
		serverSock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (serverSock == INVALID_SOCKET) continue;

		// Set connect timeout
		DWORD timeout = 15000;
		setsockopt(serverSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
		setsockopt(serverSock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

		if (connect(serverSock, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
			closesocket(serverSock);
			serverSock = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (serverSock == INVALID_SOCKET) {
		LogError(L"[NetworkFilterPlugin] Failed to connect to %hs:%d", host.c_str(), port);
		return false;
	}

	serverSocket = (void*)serverSock;
	return true;
}

// ========================================================================
// Connection Handler (runs in per-connection thread)
// ========================================================================

bool NetworkFilterPlugin::HandleClientConnection(void* clientSocket) {
	g_State.activeConnections++;
	SOCKET client = (SOCKET)clientSocket;

	auto cleanup = [&]() {
		closesocket(client);
		g_State.activeConnections--;
	};

	// --- Read request line ---
	std::string requestLine = ReadLine(clientSocket);
	if (requestLine.empty()) {
		cleanup();
		return false;
	}

	std::string method, url, version;
	if (!ParseRequestLine(requestLine, method, url, version)) {
		LogProxyError(L"Invalid request line from client");
		SendErrorResponse(clientSocket, 400, "Bad Request", "Invalid request line");
		cleanup();
		return false;
	}

	// --- Extract host and port using improved parsing ---
	std::string host;
	int port = 443; // default for CONNECT

	if (_stricmp(method.c_str(), "CONNECT") == 0) {
		// CONNECT host:port HTTP/1.1
		ExtractHostPortFromUrl(url, host, port, 443);
	}
	else {
		// GET http://host:port/path HTTP/1.1
		ExtractHostPortFromUrl(url, host, port, 80);
	}

	if (host.empty()) {
		LogProxyError(L"Could not extract host from URL");
		SendErrorResponse(clientSocket, 400, "Bad Request", "Invalid URL");
		cleanup();
		return false;
	}

	// --- Domain whitelist check (pure hostname, no port) ---
	std::wstring domainW = StringToWide(host);

	bool allowed = false;
	std::wstring matchedPatternStr;
	{
		std::lock_guard<std::mutex> lock(g_State.mutex);
		for (const auto& pattern : g_State.allowedDomains) {
			if (MatchDomainPattern(pattern.pattern, domainW)) {
				matchedPatternStr = pattern.pattern;
				allowed = true;
				break;
			}
		}
	}

	std::wstring methodW = StringToWide(method);
	if (allowed) {
		LogProxyAllow(methodW.c_str(), domainW.c_str(), matchedPatternStr.c_str());
	}
	else {
		LogProxyBlock(methodW.c_str(), domainW.c_str(), L"no matching rule");
		SendErrorResponse(clientSocket, 403, "Forbidden",
			"Access to this domain is not allowed by network filter");
		cleanup();
		return false;
	}

	// ================================================================
	// CONNECT tunnel (HTTPS)
	// ================================================================
	if (_stricmp(method.c_str(), "CONNECT") == 0) {
		// Drain remaining CONNECT request headers
		std::string headerLine;
		while (!(headerLine = ReadLine(clientSocket)).empty()) {
			// Discard CONNECT headers (Host, Proxy-Connection, etc.)
		}

		void* serverSocket = nullptr;
		if (!ConnectToServer(host, port, serverSocket)) {
			LogProxyError(L"CONNECT tunnel failed: cannot reach %hs:%d", host.c_str(), port);
			SendErrorResponse(clientSocket, 502, "Bad Gateway",
				"Failed to connect to target server");
			cleanup();
			return false;
		}

		std::string connectResponse = "HTTP/1.1 200 Connection Established\r\n\r\n";
		send(client, connectResponse.c_str(), (int)connectResponse.size(), 0);

		HandleHttpsTunnel(clientSocket, serverSocket);

		closesocket((SOCKET)serverSocket);
	}
	// ================================================================
	// HTTP plaintext forwarding
	// ================================================================
	else {
		void* serverSocket = nullptr;
		if (!ConnectToServer(host, port, serverSocket)) {
			LogProxyError(L"HTTP forward failed: cannot reach %hs:%d", host.c_str(), port);
			SendErrorResponse(clientSocket, 502, "Bad Gateway",
				"Failed to connect to target server");
			cleanup();
			return false;
		}

		SOCKET server = (SOCKET)serverSocket;
		std::string fullRequest = requestLine + "\r\n";

		// Read request headers, parse Content-Length and Transfer-Encoding
		long long contentLength = -1;
		bool chunkedEncoding = false;
		bool hasConnectionHeader = false;

		std::string headerLine;
		while (!(headerLine = ReadLine(clientSocket)).empty()) {
			// Skip client's Connection header; we'll force "close"
			if (_strnicmp(headerLine.c_str(), "Connection:", 11) == 0) {
				hasConnectionHeader = true;
				continue; // Don't forward; we'll replace it below
			}
			// Skip Proxy-Connection header
			if (_strnicmp(headerLine.c_str(), "Proxy-Connection:", 17) == 0) {
				continue;
			}

			fullRequest += headerLine + "\r\n";

			if (_strnicmp(headerLine.c_str(), "Content-Length:", 15) == 0) {
				const char* val = headerLine.c_str() + 15;
				while (*val == ' ' || *val == '\t') val++;
				try { contentLength = std::stoll(val); }
				catch (...) { contentLength = -1; }
			}

			if (_strnicmp(headerLine.c_str(), "Transfer-Encoding:", 18) == 0) {
				std::string val = headerLine.substr(18);
				size_t s = val.find_first_not_of(" \t");
				if (s != std::string::npos) val = val.substr(s);
				std::string valLower = val;
				std::transform(valLower.begin(), valLower.end(), valLower.begin(), ::tolower);
				if (valLower.find("chunked") != std::string::npos) {
					chunkedEncoding = true;
				}
			}
		}

		// Inject "launchapp" header
		std::string launchAppVal = GetLaunchAppHeaderValue();
		fullRequest += "launchapp: " + launchAppVal + "\r\n";

		// Force Connection: close so the server closes after response,
		// making our response forwarding reliable.
		fullRequest += "Connection: close\r\n";

		fullRequest += "\r\n";

		// Send request headers
		send(server, fullRequest.c_str(), (int)fullRequest.size(), 0);

		LogProxyInfo(L"[NetworkFilterPlugin] Injected header: launchapp=%hs", launchAppVal.c_str());

		// Forward request body
		if (chunkedEncoding) {
			ForwardChunkedBody(clientSocket, serverSocket);
		}
		else if (contentLength > 0) {
			ForwardRequestBody(clientSocket, serverSocket, contentLength);
		}

		// Forward full HTTP response back to client
		ForwardHttpResponse(serverSocket, clientSocket);

		closesocket(server);
	}

	cleanup();
	return true;
}

// ========================================================================
// HTTP Response Forwarding (parses headers for proper body handling)
// ========================================================================

bool NetworkFilterPlugin::ForwardHttpResponse(void* serverSock, void* clientSock) {
	SOCKET src = (SOCKET)serverSock;
	SOCKET dst = (SOCKET)clientSock;

	// 1) Read and forward response headers, detect body framing
	std::string responseHeaders;
	long long contentLength = -1;
	bool chunkedResponse = false;
	bool connectionClose = false;

	std::string headerLine;
	while (!(headerLine = ReadLine(serverSock)).empty()) {
		responseHeaders += headerLine + "\r\n";

		if (_strnicmp(headerLine.c_str(), "Content-Length:", 15) == 0) {
			const char* val = headerLine.c_str() + 15;
			while (*val == ' ' || *val == '\t') val++;
			try { contentLength = std::stoll(val); }
			catch (...) { contentLength = -1; }
		}
		if (_strnicmp(headerLine.c_str(), "Transfer-Encoding:", 18) == 0) {
			std::string val = headerLine.substr(18);
			std::string valLower;
			for (char c : val) valLower += (char)tolower((unsigned char)c);
			if (valLower.find("chunked") != std::string::npos) {
				chunkedResponse = true;
			}
		}
		if (_strnicmp(headerLine.c_str(), "Connection:", 11) == 0) {
			std::string val = headerLine.substr(11);
			std::string valLower;
			for (char c : val) valLower += (char)tolower((unsigned char)c);
			if (valLower.find("close") != std::string::npos) {
				connectionClose = true;
			}
		}
	}
	responseHeaders += "\r\n"; // End of headers

	// Send headers to client
	if (send(dst, responseHeaders.c_str(), (int)responseHeaders.size(), 0) <= 0) {
		LogProxyWarn(L"ForwardHttpResponse: failed to send response headers");
		return false;
	}

	// 2) Forward body based on framing
	if (chunkedResponse) {
		// Forward chunked response body (server -> client)
		return ForwardChunkedBody(serverSock, clientSock);
	}
	else if (contentLength > 0) {
		// Forward exact Content-Length bytes
		return ForwardRequestBody(serverSock, clientSock, contentLength);
	}
	else if (contentLength == 0) {
		// No body
		return true;
	}
	else {
		// No Content-Length, not chunked: read until server closes connection
		// (this is the fallback, works because we forced Connection: close)
		return ForwardData(serverSock, clientSock);
	}
}

// ========================================================================
// Data Forwarding Primitives
// ========================================================================

bool NetworkFilterPlugin::ForwardRequestBody(void* src, void* dst, long long contentLength) {
	SOCKET s = (SOCKET)src;
	SOCKET d = (SOCKET)dst;
	char buffer[8192];

	long long remaining = contentLength;
	while (remaining > 0 && g_State.running) {
		int toRead = (remaining > (long long)sizeof(buffer))
			? (int)sizeof(buffer) : (int)remaining;

		int recvLen = recv(s, buffer, toRead, 0);
		if (recvLen <= 0) {
			if (recvLen < 0) {
				LogProxyWarn(L"ForwardRequestBody recv() failed: %d", WSAGetLastError());
			}
			return false;
		}

		int sent = 0;
		while (sent < recvLen) {
			int sendResult = send(d, buffer + sent, recvLen - sent, 0);
			if (sendResult <= 0) {
				LogProxyWarn(L"ForwardRequestBody send() failed: %d", WSAGetLastError());
				return false;
			}
			sent += sendResult;
		}
		remaining -= recvLen;
	}
	return (remaining == 0);
}

bool NetworkFilterPlugin::ForwardChunkedBody(void* src, void* dst) {
	SOCKET d = (SOCKET)dst;
	char buffer[8192];

	while (g_State.running) {
		// 1) Read chunk size line
		std::string sizeLine = ReadLine(src);
		std::string sizeLineRaw = sizeLine + "\r\n";
		if (send(d, sizeLineRaw.c_str(), (int)sizeLineRaw.size(), 0) <= 0) {
			LogProxyWarn(L"ForwardChunkedBody send chunk-size failed: %d", WSAGetLastError());
			return false;
		}

		// 2) Parse chunk size
		long long chunkSize = 0;
		try {
			std::string hexPart = sizeLine;
			size_t semiPos = hexPart.find(';');
			if (semiPos != std::string::npos) hexPart = hexPart.substr(0, semiPos);
			while (!hexPart.empty() && (hexPart.back() == ' ' || hexPart.back() == '\t'))
				hexPart.pop_back();
			chunkSize = std::stoll(hexPart, nullptr, 16);
		}
		catch (...) {
			LogProxyWarn(L"ForwardChunkedBody: failed to parse chunk size");
			return false;
		}

		// 3) Terminal chunk
		if (chunkSize == 0) {
			std::string trailerLine;
			while (!(trailerLine = ReadLine(src)).empty()) {
				std::string raw = trailerLine + "\r\n";
				send(d, raw.c_str(), (int)raw.size(), 0);
			}
			const char* endBlock = "\r\n";
			send(d, endBlock, 2, 0);
			return true;
		}

		// 4) Forward chunk data
		SOCKET s = (SOCKET)src;
		long long remaining = chunkSize;
		while (remaining > 0) {
			int toRead = (remaining > (long long)sizeof(buffer))
				? (int)sizeof(buffer) : (int)remaining;
			int recvLen = recv(s, buffer, toRead, 0);
			if (recvLen <= 0) {
				LogProxyWarn(L"ForwardChunkedBody recv chunk data failed: %d", WSAGetLastError());
				return false;
			}
			int sent = 0;
			while (sent < recvLen) {
				int sendResult = send(d, buffer + sent, recvLen - sent, 0);
				if (sendResult <= 0) {
					LogProxyWarn(L"ForwardChunkedBody send chunk data failed: %d", WSAGetLastError());
					return false;
				}
				sent += sendResult;
			}
			remaining -= recvLen;
		}

		// 5) CRLF after chunk data
		std::string chunkEnd = ReadLine(src);
		std::string chunkEndRaw = chunkEnd + "\r\n";
		send(d, chunkEndRaw.c_str(), (int)chunkEndRaw.size(), 0);
	}
	return false;
}

bool NetworkFilterPlugin::HandleHttpsTunnel(void* client, void* server) {
	SOCKET c = (SOCKET)client;
	SOCKET s = (SOCKET)server;
	char buffer[4096];

	while (g_State.running) {
		fd_set readSet;
		FD_ZERO(&readSet);
		FD_SET(c, &readSet);
		FD_SET(s, &readSet);

		SOCKET maxFd = (c > s) ? c : s;
		timeval timeout;
		timeout.tv_sec = 300;
		timeout.tv_usec = 0;
		int selectResult = select((int)maxFd + 1, &readSet, nullptr, nullptr, &timeout);

		if (selectResult == 0) {
			LogProxyWarn(L"HTTPS tunnel timeout after 300 seconds of inactivity");
			break;
		}
		if (selectResult < 0) {
			int err = WSAGetLastError();
			LogProxyWarn(L"HTTPS tunnel select() error: %d", err);
			break;
		}

		bool shouldBreak = false;

		if (FD_ISSET(c, &readSet)) {
			int recvLen = recv(c, buffer, sizeof(buffer), 0);
			if (recvLen <= 0) break;
			int sent = 0;
			while (sent < recvLen) {
				int sendResult = send(s, buffer + sent, recvLen - sent, 0);
				if (sendResult <= 0) {
					LogProxyWarn(L"HTTPS tunnel send() to server failed: %d", WSAGetLastError());
					shouldBreak = true;
					break;
				}
				sent += sendResult;
			}
			if (shouldBreak) break;
		}

		if (FD_ISSET(s, &readSet)) {
			int recvLen = recv(s, buffer, sizeof(buffer), 0);
			if (recvLen <= 0) break;
			int sent = 0;
			while (sent < recvLen) {
				int sendResult = send(c, buffer + sent, recvLen - sent, 0);
				if (sendResult <= 0) {
					LogProxyWarn(L"HTTPS tunnel send() to client failed: %d", WSAGetLastError());
					shouldBreak = true;
					break;
				}
				sent += sendResult;
			}
			if (shouldBreak) break;
		}
	}
	return true;
}

bool NetworkFilterPlugin::ForwardData(void* src, void* dst) {
	SOCKET s = (SOCKET)src;
	SOCKET d = (SOCKET)dst;
	char buffer[8192];

	while (g_State.running) {
		int recvLen = recv(s, buffer, sizeof(buffer), 0);
		if (recvLen <= 0) {
			if (recvLen < 0) {
				int err = WSAGetLastError();
				// WSAETIMEDOUT is expected when server takes long to close
				if (err != WSAETIMEDOUT) {
					LogProxyWarn(L"ForwardData recv() failed: %d", err);
				}
			}
			break;
		}

		int sent = 0;
		while (sent < recvLen) {
			int sendResult = send(d, buffer + sent, recvLen - sent, 0);
			if (sendResult <= 0) {
				LogProxyWarn(L"ForwardData send() failed: %d", WSAGetLastError());
				return false;
			}
			sent += sendResult;
		}
	}
	return true;
}

// ========================================================================
// Per-Connection Thread Entry Point
// ========================================================================

unsigned long __stdcall NetworkFilterPlugin::ClientConnectionThread(void* param) {
	SOCKET clientSocket = (SOCKET)(uintptr_t)param;
	HandleClientConnection((void*)clientSocket);
	return 0;
}

// ========================================================================
// Server Accept Loop (multi-threaded: spawns a thread per connection)
// ========================================================================

unsigned long __stdcall NetworkFilterPlugin::ProxyServerThread(void* param) {
	(void)param;
	LogInfo(L"[NetworkFilterPlugin] Proxy server thread started.");

	while (g_State.running) {
		sockaddr_in clientAddr;
		int addrLen = sizeof(clientAddr);
		SOCKET clientSocket = accept((SOCKET)g_State.listenSocket,
			(sockaddr*)&clientAddr, &addrLen);

		if (!g_State.running) break;

		if (clientSocket == INVALID_SOCKET) {
			int err = WSAGetLastError();
			if (err != WSAEINTR && err != WSAENOTSOCK) {
				LogError(L"[NetworkFilterPlugin] accept() failed: %d", err);
			}
			continue;
		}

		DWORD clientIp = clientAddr.sin_addr.s_addr;
		LogDebug(L"[NetworkFilterPlugin] Client connected from %d.%d.%d.%d",
			clientIp & 0xFF, (clientIp >> 8) & 0xFF,
			(clientIp >> 16) & 0xFF, (clientIp >> 24) & 0xFF);

		// ★ Multi-threaded: spawn a new thread for each client connection
		HANDLE hThread = CreateThread(nullptr, 0, ClientConnectionThread,
			(void*)(uintptr_t)clientSocket, 0, nullptr);
		if (hThread) {
			CloseHandle(hThread); // Detach - thread runs independently
		}
		else {
			LogError(L"[NetworkFilterPlugin] CreateThread for client failed: %d", GetLastError());
			closesocket(clientSocket);
		}
	}

	LogInfo(L"[NetworkFilterPlugin] Proxy server thread exiting.");
	return 0;
}

