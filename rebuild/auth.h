// ============================================================================
// AxonSkin v4.1 - 认证系统
// 基于 axonlogin.dll 完整反编译 (1079 函数, 1.08MB 伪代码)
// 服务器: 124.222.192.168:9486
// 协议: 自定义 TCP + XOR 加密
// ============================================================================

#pragma once
#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class AuthSystem {
public:
    // 认证状态
    enum class AuthStatus {
        Idle = 0,
        Connecting,
        Authenticating,
        Success,
        Failed,
        TrialExpired,
        IPMismatch,
        NoUnbindCount,
        NetworkError
    };
    
    // 错误码 (来自 axonlogin.dll sub_180006560 switch-case)
    enum class AuthErrorCode {
        Success = 0,
        InvalidKey = -1,
        TrialCannotUnbind = -2,
        AllKeysBlocked = -3,
        IPMachineMismatch = -4,
        KeyExpired = -5,
        KeyBanned = -6,
        VersionTooOld = -7,
        ServerError = -8,
        AlreadyBound = -9,
        TrialUsedUp = -10
    };
    
    struct AuthResult {
        AuthStatus status = AuthStatus::Idle;
        AuthErrorCode errorCode = AuthErrorCode::Success;
        std::wstring expiryTime;      // 过期时间字符串
        std::wstring sessionToken;   // 会话令牌
        int remainingDays = 0;       // 剩余天数
        int unbindCount = 0;         // 剩余解绑次数
    };

private:
    static constexpr const char* AUTH_SERVER = "124.222.192.168";
    static constexpr int AUTH_PORT = 9486;
    static constexpr uint8_t XOR_KEY = 0x2F;
    static constexpr int MAX_RETRIES = 3;
    static constexpr int RETRY_DELAY_MS = 300;
    static constexpr int VERSION = 4;
    
    std::wstring m_cardKey;
    std::wstring m_machineId;
    AuthResult m_result;
    
public:
    AuthSystem() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        m_machineId = Utils::GetMachineId();
    }
    
    ~AuthSystem() {
        WSACleanup();
    }
    
    // 试用登录 (sub_1800076D0)
    // 创建 Dlg_RMBind 对话框 (资源 0x6B "已绑定机器码信息")
    bool TryTrialLogin() {
        m_machineId = Utils::GetMachineId();
        if (m_machineId.empty()) {
            MessageBoxW(nullptr, L"未绑定机器码", L"提示", MB_ICONERROR);
            return false;
        }
        
        // 检查试用是否已用完
        int trialCount = ReadTrialCount();
        if (trialCount <= 0) {
            // "现在试用那个选项没了" — 一次性试用已耗尽
            return false;
        }
        
        // 试用认证请求
        AuthResult result = SendAuthRequest("", m_machineId, 0x01);  // cmd=0x01 trial
        
        if (result.status == AuthStatus::Success) {
            // 减少试用次数
            WriteTrialCount(trialCount - 1);
            m_result = result;
            return true;
        }
        
        return false;
    }
    
    // 卡密登录 (sub_180006560)
    // 创建 Dlg_OnlineClient 对话框 (资源 0x6A "在线客户端信息")
    bool TryCardKeyLogin(const std::wstring& cardKey) {
        // 验证卡密长度 (32-40 字符)
        if (cardKey.length() < 32 || cardKey.length() > 40) {
            MessageBoxW(nullptr, L"卡密长度不符!", L"错误", MB_ICONERROR);
            return false;
        }
        
        m_cardKey = cardKey;
        m_machineId = Utils::GetMachineId();
        
        // 在线认证请求 (cmd=0x02 auth)
        AuthResult result = SendAuthRequest(
            Utils::WToU8(cardKey), 
            Utils::WToU8(m_machineId), 
            0x02
        );
        
        // 处理错误码 (来自 switch-case)
        if (result.status != AuthStatus::Success) {
            ShowAuthError(result.errorCode);
            return false;
        }
        
        m_result = result;
        
        // 最终验证 (sub_1800091D0)
        return FinalVerification();
    }
    
    // 最终验证 (sub_1800091D0)
    // 分配 3 个缓冲区 (2049B, 101B, 129B)
    // 调用主程序回调 (qword_180050B80 + 0x90)
    // 重试 3 次 × 300ms, 失败 ExitProcess(0)
    bool FinalVerification() {
        // 分配缓冲区
        std::vector<char> buf1(2049, 0);  // 认证响应数据
        std::vector<char> buf2(101, 0);    // 卡密/会话信息
        std::vector<char> buf3(129, 0);    // 机器码信息
        
        int result = 0;
        int versionRequired = 0;
        
        // 重试 3 次
        for (int i = 0; i < MAX_RETRIES; i++) {
            result = VerifyOnline(buf1.data(), buf2.data(), buf3.data(), 
                                  &versionRequired);
            if (result == 1) break;
            Sleep(RETRY_DELAY_MS);
        }
        
        // 验证条件: result==1 AND (versionRequired==0 OR currentVersion>=versionRequired)
        if (result != 1 || 
            (versionRequired != 0 && VERSION < versionRequired)) {
            // 失败: 1200ms 等待后退出
            Sleep(1200);  // 0x4B0 ms
            return false;
        }
        
        return true;
    }
    
    // 机器码解绑
    bool UnbindMachine() {
        int remaining = ReadUnbindCount();
        if (remaining <= 0) {
            MessageBoxW(nullptr, 
                L"已达最多解绑次数, 无法解绑!",
                L"提示", MB_ICONWARNING);
            return false;
        }
        
        // "本次解绑将消耗赠送的解绑次数(剩余: %d) 是否前往解绑页面?"
        wchar_t msg[256];
        swprintf(msg, L"本次解绑将消耗赠送的解绑次数(剩余: %d) 是否前往解绑页面?", remaining);
        
        if (MessageBoxW(nullptr, msg, L"提示", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            // 解绑请求
            AuthResult result = SendAuthRequest("", m_machineId, 0x03);  // cmd=0x03 unbind
            
            if (result.status == AuthStatus::Success) {
                // "本次解绑不扣除时长! %s 内剩余解绑次数: %d (含本次)"
                WriteUnbindCount(remaining - 1);
                return true;
            }
        }
        
        return false;
    }
    
    const AuthResult& GetResult() const { return m_result; }
    
private:
    // 发送认证请求到 124.222.192.168:9486
    AuthResult SendAuthRequest(const std::string& cardKey, 
                                const std::string& machineId,
                                uint8_t cmd) {
        AuthResult result;
        result.status = AuthStatus::Connecting;
        
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            result.status = AuthStatus::NetworkError;
            return result;
        }
        
        // 连接
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(AUTH_PORT);
        inet_pton(AF_INET, AUTH_SERVER, &addr.sin_addr);
        
        // 设置超时
        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(sock);
            result.status = AuthStatus::NetworkError;
            return result;
        }
        
        result.status = AuthStatus::Authenticating;
        
        // 构建请求包
        // 载荷结构: 卡密(32B) + 机器码(4B) + 版本号(4B) = 40B
        std::vector<uint8_t> payload(40, 0);
        
        // 填充卡密
        memcpy(payload.data(), cardKey.c_str(), min(cardKey.size(), (size_t)32));
        
        // 填充机器码 (后4字节)
        uint32_t machineHash = HashMachineId(machineId);
        memcpy(payload.data() + 32, &machineHash, 4);
        
        // 填充版本号
        uint32_t ver = VERSION;
        memcpy(payload.data() + 36, &ver, 4);
        
        // XOR 加密载荷
        for (auto& b : payload) b ^= XOR_KEY;
        
        // 封包: length(4) + cmd(1) + payload(40) = 45 bytes
        std::vector<uint8_t> packet;
        uint32_t pktLen = 1 + payload.size();  // cmd + payload
        packet.resize(4 + pktLen);
        memcpy(packet.data(), &pktLen, 4);
        packet[4] = cmd;
        memcpy(packet.data() + 5, payload.data(), payload.size());
        
        // 发送
        if (send(sock, (char*)packet.data(), packet.size(), 0) == SOCKET_ERROR) {
            closesocket(sock);
            result.status = AuthStatus::NetworkError;
            return result;
        }
        
        // 接收响应 (166 bytes)
        std::vector<uint8_t> response(1024, 0);
        int recvLen = recv(sock, (char*)response.data(), response.size(), 0);
        closesocket(sock);
        
        if (recvLen <= 0) {
            result.status = AuthStatus::NetworkError;
            return result;
        }
        
        // 解析响应
        // length(4) + data
        uint32_t respLen = 0;
        memcpy(&respLen, response.data(), 4);
        
        if (recvLen < (int)(4 + respLen) || respLen < 10) {
            result.status = AuthStatus::NetworkError;
            return result;
        }
        
        // 解密响应数据
        std::vector<uint8_t> respData(response.begin() + 4, 
                                       response.begin() + 4 + respLen);
        for (auto& b : respData) b ^= XOR_KEY;
        
        // 解析响应字段
        // status(1) + errorCode(1) + expiryTime(20) + remaining(4) + unbind(4) + ...
        if (respData.size() >= 30) {
            uint8_t status = respData[0];
            int8_t errorCode = (int8_t)respData[1];
            
            if (status == 1) {
                result.status = AuthStatus::Success;
                result.errorCode = AuthErrorCode::Success;
                
                // 过期时间 (YYYY-MM-DD HH:MM:SS)
                char expiry[21] = {};
                memcpy(expiry, respData.data() + 2, 20);
                result.expiryTime = Utils::U8ToW(expiry);
                
                // 剩余天数
                if (respData.size() >= 26) {
                    memcpy(&result.remainingDays, respData.data() + 22, 4);
                }
                
                // 解绑次数
                if (respData.size() >= 30) {
                    memcpy(&result.unbindCount, respData.data() + 26, 4);
                }
            } else {
                result.status = AuthStatus::Failed;
                result.errorCode = (AuthErrorCode)errorCode;
            }
        }
        
        return result;
    }
    
    // 主程序回调验证 (qword_180050B80 + 0x90)
    int VerifyOnline(char* buf1, char* buf2, char* buf3, int* versionRequired) {
        // 在原始程序中，这是通过虚函数表调用主程序的认证回调
        // 重建时直接调用 SendAuthRequest 的缓存结果
        if (m_result.status == AuthStatus::Success) {
            *versionRequired = 0;  // 不检查版本
            return 1;
        }
        return 0;
    }
    
    void ShowAuthError(AuthErrorCode code) {
        struct { AuthErrorCode code; const wchar_t* msg; } errors[] = {
            { AuthErrorCode::InvalidKey,        L"卡密无效!" },
            { AuthErrorCode::TrialCannotUnbind, L"但试用卡无法解绑!" },
            { AuthErrorCode::AllKeysBlocked,    L"该代理下所有卡密无法登录!" },
            { AuthErrorCode::IPMachineMismatch, L"IP、机器码不符!" },
            { AuthErrorCode::KeyExpired,        L"卡密已过期!" },
            { AuthErrorCode::KeyBanned,         L"卡密已被封禁!" },
            { AuthErrorCode::VersionTooOld,     L"当前版本过低,请更新!" },
            { AuthErrorCode::ServerError,       L"服务器错误!" },
            { AuthErrorCode::AlreadyBound,      L"该卡密已绑定其他机器!" },
            { AuthErrorCode::TrialUsedUp,       L"试用次数已用完!" },
        };
        
        for (auto& e : errors) {
            if (e.code == code) {
                MessageBoxW(nullptr, e.msg, L"提示", MB_ICONWARNING);
                return;
            }
        }
    }
    
    uint32_t HashMachineId(const std::string& id) {
        uint32_t hash = 0;
        for (char c : id) {
            hash = hash * 31 + c;
        }
        return hash;
    }
    
    // 注册表读写 (HKEY_CURRENT_USER\Software\Axon\Skin)
    int ReadTrialCount() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Axon\\Skin", 
                           0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD value = 0, size = sizeof(value);
            RegQueryValueExW(hKey, L"trial_count", nullptr, nullptr, 
                            (LPBYTE)&value, &size);
            RegCloseKey(hKey);
            return value;
        }
        return 1;  // 默认 1 次试用
    }
    
    void WriteTrialCount(int count) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Axon\\Skin",
                            0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"trial_count", 0, REG_DWORD, 
                          (LPBYTE)&count, sizeof(count));
            RegCloseKey(hKey);
        }
    }
    
    int ReadUnbindCount() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Axon\\Skin",
                           0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD value = 0, size = sizeof(value);
            RegQueryValueExW(hKey, L"unbind_count", nullptr, nullptr,
                            (LPBYTE)&value, &size);
            RegCloseKey(hKey);
            return value;
        }
        return 3;  // 默认 3 次解绑
    }
    
    void WriteUnbindCount(int count) {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Axon\\Skin",
                            0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"unbind_count", 0, REG_DWORD,
                          (LPBYTE)&count, sizeof(count));
            RegCloseKey(hKey);
        }
    }
};
