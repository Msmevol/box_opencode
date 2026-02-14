#include "NetworkFilterPlugin.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#undef WIN32_LEAN_AND_MEAN

#include <algorithm>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

NetworkFilterState NetworkFilterPlugin::g_State;

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
    addr.sin_port = htons(g_State.port);
    
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
    
    WSACleanup();
    
    LogInfo(L"[NetworkFilterPlugin] Shutdown complete.");
    LogProxyInfo(L"========== Proxy stopped ==========");
}

void NetworkFilterPlugin::SetAllowedDomains(const std::vector<std::wstring>& domains) {
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
    
    // Log domain rules to proxy log for visibility
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

bool NetworkFilterPlugin::MatchDomainPattern(const std::wstring& pattern, const std::wstring& domain) {
    if (pattern.empty() || domain.empty()) {
        return false;
    }
    
    size_t wildcardPos = pattern.find(L'*');
    
    if (wildcardPos == std::wstring::npos) {
        return _wcsicmp(pattern.c_str(), domain.c_str()) == 0;
    }
    
    if (wildcardPos != 0 || pattern.size() < 2) {
        LogWarn(L"[NetworkFilterPlugin] Invalid wildcard pattern: %ls", pattern.c_str());
        return false;
    }
    
    std::wstring suffix = pattern.substr(1);
    
    if (domain.size() < suffix.size()) {
        return false;
    }
    
    std::wstring domainSuffix = domain.substr(domain.size() - suffix.size());
    
    return _wcsicmp(suffix.c_str(), domainSuffix.c_str()) == 0;
}

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

bool NetworkFilterPlugin::ParseRequestLine(const std::string& line, 
                                        std::string& method, 
                                        std::string& url, 
                                        std::string& version) {
    method.clear();
    url.clear();
    version.clear();
    
    size_t pos1 = line.find(' ');
    if (pos1 == std::string::npos) return false;
    
    size_t pos2 = line.find(' ', pos1 + 1);
    if (pos2 == std::string::npos) return false;
    
    method = line.substr(0, pos1);
    url = line.substr(pos1 + 1, pos2 - pos1 - 1);
    version = line.substr(pos2 + 1);
    
    return true;
}

std::string NetworkFilterPlugin::ExtractDomainFromUrl(const std::string& url) {
    if (url.empty()) return "";
    
    size_t start = 0;
    
    if (url.find("://") != std::string::npos) {
        start = url.find("://") + 3;
    }
    
    size_t end = url.find('/', start);
    if (end == std::string::npos) {
        end = url.find(':', start);
    }
    if (end == std::string::npos) {
        end = url.size();
    }
    
    return url.substr(start, end - start);
}

std::string NetworkFilterPlugin::ReadLine(void* sock) {
    SOCKET s = (SOCKET)sock;
    std::string result;
    char ch;
    
    while (true) {
        int recvResult = recv(s, &ch, 1, 0);
        if (recvResult <= 0) {
            break;
        }
        
        if (ch == '\r') {
            continue;
        }
        
        if (ch == '\n') {
            break;
        }
        
        result += ch;
        
        if (result.size() > 8192) {
            break;
        }
    }
    
    return result;
}

bool NetworkFilterPlugin::SendErrorResponse(void* sock, int code, const char* status, const char* body) {
    SOCKET s = (SOCKET)sock;
    char response[512];
    int len = sprintf_s(response, sizeof(response),
                      "HTTP/1.1 %d %s\r\n"
                      "Content-Type: text/plain\r\n"
                      "Content-Length: %zu\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "%s",
                      code, status, strlen(body), body);
    
    if (len > 0) {
        send(s, response, len, 0);
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
        if (serverSock == INVALID_SOCKET) {
            continue;
        }
        
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

bool NetworkFilterPlugin::HandleClientConnection(void* clientSocket) {
    SOCKET client = (SOCKET)clientSocket;
    std::string requestLine = ReadLine(clientSocket);
    if (requestLine.empty()) {
        closesocket(client);
        return false;
    }
    
    std::string method, url, version;
    if (!ParseRequestLine(requestLine, method, url, version)) {
        LogProxyError(L"Invalid request line from client");
        SendErrorResponse(clientSocket, 400, "Bad Request", "Invalid request line");
        closesocket(client);
        return false;
    }
    
    std::string domain = ExtractDomainFromUrl(url);
    if (domain.empty()) {
        LogProxyError(L"Could not extract domain from URL");
        SendErrorResponse(clientSocket, 400, "Bad Request", "Invalid URL");
        closesocket(client);
        return false;
    }
    
    std::wstring domainW = StringToWide(domain);
    
    bool allowed = false;
    std::wstring matchedPatternStr;
    for (const auto& pattern : g_State.allowedDomains) {
        if (MatchDomainPattern(pattern.pattern, domainW)) {
            matchedPatternStr = pattern.pattern;
            allowed = true;
            break;
        }
    }
    
    std::wstring methodW = StringToWide(method);
    if (allowed) {
        LogProxyAllow(methodW.c_str(), domainW.c_str(), matchedPatternStr.c_str());
    } else {
        LogProxyBlock(methodW.c_str(), domainW.c_str(), L"no matching rule");
        SendErrorResponse(clientSocket, 403, "Forbidden", 
                       "Access to this domain is not allowed by network filter");
        closesocket(client);
        return false;
    }
    
    int port = 443;
    size_t portPos = domain.find(':');
    std::string host = domain;
    if (portPos != std::string::npos) {
        host = domain.substr(0, portPos);
        port = std::stoi(domain.substr(portPos + 1));
    }
    
    if (_stricmp(method.c_str(), "CONNECT") == 0) {
        void* serverSocket = nullptr;
        if (!ConnectToServer(host, port, serverSocket)) {
            LogProxyError(L"CONNECT tunnel failed: cannot reach %hs:%d", host.c_str(), port);
            SendErrorResponse(clientSocket, 502, "Bad Gateway", 
                           "Failed to connect to target server");
            closesocket(client);
            return false;
        }
        
        std::string connectResponse = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(client, connectResponse.c_str(), (int)connectResponse.size(), 0);
        
        HandleHttpsTunnel(clientSocket, serverSocket);
        
        closesocket((SOCKET)serverSocket);
    } else {
        void* serverSocket = nullptr;
        if (!ConnectToServer(host, port, serverSocket)) {
            LogProxyError(L"HTTP forward failed: cannot reach %hs:%d", host.c_str(), port);
            SendErrorResponse(clientSocket, 502, "Bad Gateway", 
                           "Failed to connect to target server");
            closesocket(client);
            return false;
        }
        
        SOCKET server = (SOCKET)serverSocket;
        std::string fullRequest = requestLine + "\r\n";
        std::string headerLine;
        while (!(headerLine = ReadLine(clientSocket)).empty()) {
            fullRequest += headerLine + "\r\n";
        }
        fullRequest += "\r\n";
        
        send(server, fullRequest.c_str(), (int)fullRequest.size(), 0);
        
        ForwardData(serverSocket, clientSocket);
        
        closesocket(server);
    }
    
    closesocket(client);
    return true;
}

bool NetworkFilterPlugin::HandleHttpsTunnel(void* client, void* server) {
    SOCKET c = (SOCKET)client;
    SOCKET s = (SOCKET)server;
    char buffer[4096];
    
    while (true) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(c, &readSet);
        FD_SET(s, &readSet);
        
        SOCKET maxFd = (c > s) ? c : s;
        int selectResult = select((int)maxFd + 1, &readSet, nullptr, nullptr, nullptr);
        
        if (selectResult <= 0) {
            break;
        }
        
        if (FD_ISSET(c, &readSet)) {
            int recvLen = recv(c, buffer, sizeof(buffer), 0);
            if (recvLen <= 0) break;
            send(s, buffer, recvLen, 0);
        }
        
        if (FD_ISSET(s, &readSet)) {
            int recvLen = recv(s, buffer, sizeof(buffer), 0);
            if (recvLen <= 0) break;
            send(c, buffer, recvLen, 0);
        }
    }
    
    return true;
}

bool NetworkFilterPlugin::ForwardData(void* src, void* dst) {
    SOCKET s = (SOCKET)src;
    SOCKET d = (SOCKET)dst;
    char buffer[8192];
    
    while (true) {
        int recvLen = recv(s, buffer, sizeof(buffer), 0);
        if (recvLen <= 0) {
            break;
        }
        
        int sent = 0;
        while (sent < recvLen) {
            int sendResult = send(d, buffer + sent, recvLen - sent, 0);
            if (sendResult <= 0) {
                break;
            }
            sent += sendResult;
        }
        
        if (sent < recvLen) {
            break;
        }
    }
    
    return true;
}

unsigned long __stdcall NetworkFilterPlugin::ProxyServerThread(void* param) {
    LogInfo(L"[NetworkFilterPlugin] Proxy server thread started.");
    
    while (g_State.running) {
        sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept((SOCKET)g_State.listenSocket, (sockaddr*)&clientAddr, &addrLen);
        
        if (!g_State.running) {
            break;
        }
        
        if (clientSocket == INVALID_SOCKET) {
            int err = WSAGetLastError();
            if (err != WSAEINTR) {
                LogError(L"[NetworkFilterPlugin] accept() failed: %d", err);
            }
            continue;
        }
        
        DWORD clientIp = clientAddr.sin_addr.s_addr;
        LogDebug(L"[NetworkFilterPlugin] Client connected from %d.%d.%d.%d",
                  clientIp & 0xFF, (clientIp >> 8) & 0xFF, 
                  (clientIp >> 16) & 0xFF, (clientIp >> 24) & 0xFF);
        
        HandleClientConnection((void*)clientSocket);
    }
    
    LogInfo(L"[NetworkFilterPlugin] Proxy server thread exiting.");
    return 0;
}
