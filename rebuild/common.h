// AxonSkin v4.1 - 完整功能重建
// 基于 IDA 逆向 + 内存分析 + 崩溃日志 + AppData 数据
// 编译: g++ -std=c++17 -o AxonSkin.exe main.cpp auth.cpp config.cpp d3d_hook.cpp input_hook.cpp ui.cpp update.cpp crash.cpp -lws2_32 -lwinhttp -ld3d9 -ld3d11 -ld3d12 -ldxgi -ldwrite -ldwmapi -luxtheme -lgdiplus -lsetupapi -lwtsapi32 -ldbghelp -lversion -lwinmm -limm32 -lshlwapi -lpsapi
//
// 架构: Qt 6.8.3 静态 GUI + D3D9/11/12 渲染覆盖层 + 输入拦截 + 云端配置 + 在线认证

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <json/json.h>  // nlohmann/json

// ============================================================================
// 前向声明
// ============================================================================
class AuthSystem;
class ConfigSystem;
class D3DHookManager;
class InputInterceptor;
class UpdateSystem;
class CrashHandler;
class UIManager;

// ============================================================================
// 全局应用对象
// ============================================================================
struct AppContext {
    HINSTANCE hInstance = nullptr;
    HWND hMainWindow = nullptr;
    std::wstring appDataPath;
    std::wstring exePath;
    std::atomic<bool> running{false};
    std::mutex mtx;
    
    std::unique_ptr<AuthSystem> auth;
    std::unique_ptr<ConfigSystem> config;
    std::unique_ptr<D3DHookManager> d3dHooks;
    std::unique_ptr<InputInterceptor> input;
    std::unique_ptr<UpdateSystem> updater;
    std::unique_ptr<CrashHandler> crash;
    std::unique_ptr<UIManager> ui;
};

extern AppContext g_app;

// ============================================================================
// 工具函数
// ============================================================================
namespace Utils {
    std::wstring GetAppDataPath() {
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path))) {
            return std::wstring(path) + L"\\Axon\\AxonSkin\\";
        }
        return L"";
    }
    
    std::string WToU8(const std::wstring& w) {
        if (w.empty()) return "";
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(len - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, nullptr, nullptr);
        return s;
    }
    
    std::wstring U8ToW(const std::string& s) {
        if (s.empty()) return L"";
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(len - 1, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
        return w;
    }
    
    std::vector<uint8_t> ReadFile(const std::wstring& path) {
        FILE* f = _wfopen(path.c_str(), L"rb");
        if (!f) return {};
        fseek(f, 0, SEEK_END);
        size_t size = ftell(f);
        fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> data(size);
        fread(data.data(), 1, size, f);
        fclose(f);
        return data;
    }
    
    bool WriteFile(const std::wstring& path, const std::vector<uint8_t>& data) {
        FILE* f = _wfopen(path.c_str(), L"wb");
        if (!f) return false;
        fwrite(data.data(), 1, data.size(), f);
        fclose(f);
        return true;
    }
    
    int64_t GetCurrentTimeMs() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }
    
    std::wstring GetMachineId() {
        // 基于 axonlogin.dll 机器码生成
        // 使用 VolumeSerialNumber + ComputerName + CPU ID
        DWORD serial = 0;
        GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
        
        wchar_t computerName[MAX_PATH];
        DWORD nameLen = MAX_PATH;
        GetComputerNameW(computerName, &nameLen);
        
        int cpuInfo[4];
        __cpuid(cpuInfo, 0);
        
        wchar_t id[64];
        swprintf(id, L"%08X%08X%08X", serial, cpuInfo[1], cpuInfo[3]);
        return id;
    }
}
