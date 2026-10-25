// ============================================================================
// AxonSkin v4.1 - 主程序入口
// 基于: PE EntryPoint (SProtect stub → SP_Init_v2 → axonlogin.dll)
// 架构: Win32 GUI + Qt 6.8.3 + D3D9/11/12 + Interception + Cloud Auth
// ============================================================================

#include "common.h"
#include "auth.h"
#include "config.h"
#include "d3d_hook.h"
#include "input_hook.h"
#include "update.h"
#include "crash.h"
#include "ui.h"

// 全局应用上下文
AppContext g_app;

// ============================================================================
// SProtect 反调试绕过 (基于 rename_windows.py 分析)
// ============================================================================
namespace AntiDebugBypass {
    // SProtect 扫描窗口标题: IDA/逆向/AxonSkin/dbg → 弹出 MessageBox 拒绝
    // 重建: 不需要反调试, 但保留检测逻辑作为参考
    
    bool CheckDebuggerWindow() {
        // SProtect 检测的关键词
        const wchar_t* blockedKeywords[] = {
            L"IDA", L"逆向", L"AxonSkin", L"dbg", L"x64dbg",
            L"OllyDbg", L"WinDbg", L"Cheat Engine", L"Process Hacker"
        };
        
        for (auto keyword : blockedKeywords) {
            HWND h = FindWindowW(nullptr, keyword);
            if (h) return true;  // 检测到调试器
        }
        return false;
    }
    
    void ShowAntiDebugWarning() {
        // "禁止调试软件, 请关闭调试器然后重新运行!"
        MessageBoxW(nullptr,
            L"禁止调试软件, 请关闭调试器然后重新运行!",
            L"安全提示", MB_ICONWARNING);
    }
}

// ============================================================================
// 初始化
// ============================================================================
bool InitializeApp() {
    g_app.hInstance = GetModuleHandleW(nullptr);
    g_app.appDataPath = Utils::GetAppDataPath();
    
    // 确保 AppData 目录存在
    CreateDirectoryW(g_app.appDataPath.c_str(), nullptr);
    CreateDirectoryW((g_app.appDataPath + L"cache\\").c_str(), nullptr);
    CreateDirectoryW((g_app.appDataPath + L"crash\\").c_str(), nullptr);
    CreateDirectoryW((g_app.appDataPath + L"drivers\\").c_str(), nullptr);
    
    // 获取 EXE 路径
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    g_app.exePath = exePath;
    
    // 初始化各子系统
    g_app.crash = std::make_unique<CrashHandler>();
    g_app.crash->Initialize();
    
    g_app.config = std::make_unique<ConfigSystem>();
    g_app.config->Initialize();
    
    g_app.auth = std::make_unique<AuthSystem>();
    
    g_app.d3dHooks = std::make_unique<D3DHookManager>();
    g_app.input = std::make_unique<InputInterceptor>();
    g_app.updater = std::make_unique<UpdateSystem>();
    g_app.ui = std::make_unique<UIManager>();
    g_app.ui->Initialize();
    
    return true;
}

// ============================================================================
// 清理
// ============================================================================
void ShutdownApp() {
    if (g_app.input) g_app.input->Shutdown();
    if (g_app.d3dHooks) g_app.d3dHooks->Shutdown();
    if (g_app.config) g_app.config->SaveLocalConfig();
}

// ============================================================================
// WinMain - 程序入口
// ============================================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPWSTR lpCmdLine, int nCmdShow) {
    // 初始化 COM
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    
    // 初始化应用
    if (!InitializeApp()) {
        MessageBoxW(nullptr, L"初始化失败!", L"错误", MB_ICONERROR);
        return 1;
    }
    
    g_app.running = true;
    
    // 检查更新 (后台线程)
    std::thread([] {
        if (g_app.updater->CheckForUpdates()) {
            // 有新版本, 在主线程提示
            PostMessageW(g_app.ui->GetMainWindow(), WM_COMMAND, 4, 0);
        }
    }).detach();
    
    // 显示登录对话框
    // (基于 axonlogin.dll SP_Init_v2 → DialogBoxParamW 0x66)
    if (!g_app.ui->ShowLoginDialog()) {
        // 登录失败或取消 → 退出
        // (sub_1800091D0 失败 → ExitProcess(0))
        ShutdownApp();
        CoUninitialize();
        return 0;
    }
    
    // 登录成功后进入主窗口消息循环
    // (壳解密 .text → 主程序 Dlg_Main 启动)
    while (g_app.running) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                g_app.running = false;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        
        // 后台任务
        if (g_app.d3dHooks) {
            // 持续扫描新窗口 (游戏窗口可能稍后打开)
            // 每 5 秒扫描一次
        }
        
        Sleep(10);  // 避免 CPU 占用过高
    }
    
    ShutdownApp();
    CoUninitialize();
    return 0;
}

// ============================================================================
// 控制台入口 (用于调试)
// ============================================================================
int main() {
    // 设置控制台 (local.json: consolePinDone)
    if (AllocConsole()) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
    
    return wWinMain(GetModuleHandleW(nullptr), nullptr, GetCommandLineW(), SW_SHOW);
}
