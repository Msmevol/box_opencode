#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <atomic>

// Sandbox log functions (writes to main sandbox log)
extern void LogInfo(const wchar_t* fmt, ...);
extern void LogWarn(const wchar_t* fmt, ...);
extern void LogError(const wchar_t* fmt, ...);
extern void LogDebug(const wchar_t* fmt, ...);

// Proxy log functions (writes to separate proxy log file)
extern void LogProxyAllow(const wchar_t* method, const wchar_t* domain, const wchar_t* matchedPattern);
extern void LogProxyBlock(const wchar_t* method, const wchar_t* domain, const wchar_t* reason);
extern void LogProxyInfo(const wchar_t* fmt, ...);
extern void LogProxyWarn(const wchar_t* fmt, ...);
extern void LogProxyError(const wchar_t* fmt, ...);

struct DomainPattern {
	std::wstring pattern;
	bool hasWildcard;
};

struct NetworkFilterState {
	std::atomic<bool> running;
	std::atomic<int> activeConnections;
	int port;
	std::vector<DomainPattern> allowedDomains;
	void* listenSocket;
	void* serverThread;
	std::mutex mutex;

	NetworkFilterState() : running(false), activeConnections(0), port(8080),
		listenSocket(nullptr), serverThread(nullptr) {}
};

class NetworkFilterPlugin {
public:
	static bool Initialize(int port = 8080);
	static void Shutdown();
	static void SetAllowedDomains(const std::vector<std::wstring>& domains);
	static bool IsRunning();
	static int GetProxyPort();
	static std::wstring GetProxyUrl();

private:
	static NetworkFilterState g_State;

	static bool MatchDomainPattern(const std::wstring& pattern, const std::wstring& domain);

	static std::wstring StringToWide(const std::string& s);
	static std::string WideToString(const std::wstring& s);

	static bool ParseRequestLine(const std::string& line,
		std::string& method, std::string& url, std::string& version);

	// Extracts pure hostname (without port) from a URL
	static std::string ExtractHostFromUrl(const std::string& url);

	// Extracts host:port pair from a URL (port may be absent)
	static void ExtractHostPortFromUrl(const std::string& url,
		std::string& outHost, int& outPort, int defaultPort);

	static std::string ReadLine(void* sock);
	static bool SendErrorResponse(void* sock, int code, const char* status, const char* body);

	static bool ConnectToServer(const std::string& host, int port, void*& serverSocket);
	static bool HandleClientConnection(void* clientSocket);
	static bool HandleHttpsTunnel(void* client, void* server);
	static bool ForwardData(void* src, void* dst);
	static bool ForwardRequestBody(void* src, void* dst, long long contentLength);
	static bool ForwardChunkedBody(void* src, void* dst);

	// Forward HTTP response with proper Content-Length / chunked / connection-close handling
	static bool ForwardHttpResponse(void* serverSock, void* clientSock);

	// Generate the "launchapp" header value: "<username>_opencode"
	static std::string GetLaunchAppHeaderValue();

	// Thread entry point for per-connection handling
	static unsigned long __stdcall ClientConnectionThread(void* param);

	// Server accept loop
	static unsigned long __stdcall ProxyServerThread(void* param);
};

