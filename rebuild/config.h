// ============================================================================
// AxonSkin v4.1 - 配置系统
// 基于: AppData\Axon\AxonSkin\ (local.json, cache\cloud-cfg.bin)
// 功能: 本地配置 + 云端配置下载/解密/缓存
// ============================================================================

#pragma once
#include "common.h"
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

class ConfigSystem {
public:
    struct LocalConfig {
        int version = 4;
        bool consolePinDone = false;
    };
    
    struct CloudConfig {
        bool valid = false;
        std::wstring skinText;
        uint32_t textColor = 0xFFFFFFFF;
        float fontSize = 16.0f;
        float opacity = 0.8f;
        float posX = 10.0f;
        float posY = 10.0f;
        bool showFPS = false;
        bool showTimer = false;
        std::wstring serverUrl;
        int checkInterval = 3600;  // seconds
    };

private:
    std::wstring m_configDir;
    std::wstring m_cacheDir;
    LocalConfig m_local;
    CloudConfig m_cloud;
    std::mutex m_mtx;
    
public:
    bool Initialize() {
        m_configDir = g_app.appDataPath;
        m_cacheDir = m_configDir + L"cache\\";
        
        // 确保目录存在
        CreateDirectoryW(m_configDir.c_str(), nullptr);
        CreateDirectoryW(m_cacheDir.c_str(), nullptr);
        
        // 加载本地配置
        LoadLocalConfig();
        
        // 加载云端配置缓存
        LoadCloudConfigCache();
        
        // 如果需要，下载最新云端配置
        DownloadCloudConfig();
        
        return true;
    }
    
    void LoadLocalConfig() {
        std::wstring path = m_configDir + L"local.json";
        auto data = Utils::ReadFile(path);
        
        if (data.empty()) {
            // 创建默认配置
            m_local.version = 4;
            m_local.consolePinDone = false;
            SaveLocalConfig();
            return;
        }
        
        // 解析 JSON
        // {"version": 4, "consolePinDone": true}
        try {
            // 简单 JSON 解析 (实际使用 json 库)
            std::string json(data.begin(), data.end());
            if (json.find("\"consolePinDone\":true") != std::string::npos) {
                m_local.consolePinDone = true;
            }
            if (json.find("\"version\":") != std::string::npos) {
                size_t pos = json.find("\"version\":");
                m_local.version = std::stoi(json.substr(pos + 11));
            }
        } catch (...) {
            m_local.version = 4;
        }
    }
    
    void SaveLocalConfig() {
        std::string json = "{\"version\":" + std::to_string(m_local.version) + 
                          ",\"consolePinDone\":" + 
                          (m_local.consolePinDone ? "true" : "false") + "}";
        
        std::vector<uint8_t> data(json.begin(), json.end());
        Utils::WriteFile(m_configDir + L"local.json", data);
    }
    
    // 加载缓存的云端配置 (cache\cloud-cfg.bin, 1814 bytes, 加密)
    void LoadCloudConfigCache() {
        std::wstring path = m_cacheDir + L"cloud-cfg.bin";
        auto data = Utils::ReadFile(path);
        
        if (data.empty()) return;
        
        // 解密 (XOR + 自定义算法)
        auto decrypted = DecryptCloudConfig(data);
        
        if (!decrypted.empty()) {
            ParseCloudConfig(decrypted);
        }
    }
    
    // 从服务器下载最新云端配置
    bool DownloadCloudConfig() {
        // 使用 WinHTTP
        HINTERNET hSession = WinHttpOpen(
            L"AxonSkin/4.1",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return false;
        
        HINTERNET hConnect = WinHttpConnect(
            hSession, L"124.222.192.168", 9486, 0);
        
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"GET", L"/api/cloud-cfg",
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        BOOL result = WinHttpSendRequest(
            hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        
        if (result) {
            result = WinHttpReceiveResponse(hRequest, nullptr);
        }
        
        if (result) {
            // 读取响应
            std::vector<uint8_t> responseData;
            DWORD bytesRead = 0;
            uint8_t buffer[4096];
            
            do {
                bytesRead = 0;
                if (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
                    responseData.insert(responseData.end(), buffer, buffer + bytesRead);
                }
            } while (bytesRead > 0);
            
            // 解密并保存
            auto decrypted = DecryptCloudConfig(responseData);
            if (!decrypted.empty()) {
                ParseCloudConfig(decrypted);
                // 缓存到文件
                Utils::WriteFile(m_cacheDir + L"cloud-cfg.bin", responseData);
            }
        }
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return result == TRUE;
    }
    
    void ReloadCloudConfig() {
        DownloadCloudConfig();
    }
    
    const CloudConfig& GetCloudConfig() const { return m_cloud; }
    const LocalConfig& GetLocalConfig() const { return m_local; }
    
    void SetConsolePinDone(bool done) {
        m_local.consolePinDone = done;
        SaveLocalConfig();
    }
    
private:
    // 解密云端配置
    // cloud-cfg.bin 加密: 基于 .a1/.rr4 中的解密函数
    // 重建: 使用 XOR + RC4 或 AES
    std::vector<uint8_t> DecryptCloudConfig(const std::vector<uint8_t>& data) {
        if (data.size() < 16) return {};
        
        // 前16字节可能是 IV/nonce
        std::vector<uint8_t> iv(data.begin(), data.begin() + 16);
        std::vector<uint8_t> encrypted(data.begin() + 16, data.end());
        
        // XOR 解密 (简化版, 实际可能更复杂)
        std::vector<uint8_t> decrypted(encrypted.size());
        const uint8_t key[] = {0x3e, 0xb4, 0x15, 0xde, 0x09, 0xf2, 0x73, 0xa0};
        
        for (size_t i = 0; i < encrypted.size(); i++) {
            decrypted[i] = encrypted[i] ^ key[i % sizeof(key)];
            // 额外混淆: 与 IV 异或
            if (i < 16) decrypted[i] ^= iv[i];
        }
        
        return decrypted;
    }
    
    // 解析云端配置 JSON
    void ParseCloudConfig(const std::vector<uint8_t>& data) {
        if (data.empty()) return;
        
        try {
            std::string json(data.begin(), data.end());
            // 简单解析 (实际使用 json 库)
            // 期望格式: {"skinText":"Axon Skin","textColor":"0xFFFFFFFF",...}
            
            // 查找关键字段
            auto findStr = [&](const std::string& key) -> std::string {
                size_t pos = json.find("\"" + key + "\":\"");
                if (pos == std::string::npos) return "";
                pos += key.size() + 4;
                size_t end = json.find("\"", pos);
                return json.substr(pos, end - pos);
            };
            
            m_cloud.skinText = Utils::U8ToW(findStr("skinText"));
            m_cloud.serverUrl = Utils::U8ToW(findStr("serverUrl"));
            
            m_cloud.valid = true;
        } catch (...) {
            m_cloud.valid = false;
        }
    }
};
