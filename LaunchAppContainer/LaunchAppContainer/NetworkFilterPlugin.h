#pragma once

#include <string>
#include <vector>

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
    bool running;
    int port;
    std::vector<DomainPattern> allowedDomains;
    void* listenSocket;
    void* serverThread;
    
    NetworkFilterState() : running(false), port(8080), listenSocket(nullptr), serverThread(nullptr) {}
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
                               std::string& method, 
                               std::string& url, 
                               std::string& version);
    
    static std::string ExtractDomainFromUrl(const std::string& url);
    
    static std::string ReadLine(void* sock);
    
    static bool SendErrorResponse(void* sock, int code, const char* status, const char* body);
    
    static bool ConnectToServer(const std::string& host, int port, void*& serverSocket);
    
    static bool HandleClientConnection(void* clientSocket);
    
    static bool HandleHttpsTunnel(void* client, void* server);
    
    static bool ForwardData(void* src, void* dst);
    
    static unsigned long __stdcall ProxyServerThread(void* param);
};
