// ============================================================================
// AxonSkin v4.1 - 输入拦截系统
// 基于: interception.dll, interception.pending, AppData\drivers\
// 功能: 键盘/鼠标输入拦截 → 皮肤热键触发
// ============================================================================

#pragma once
#include "common.h"
#include <setupapi.h>
#include <hidsdi.h>
#pragma comment(lib, "setupapi.lib")

class InputInterceptor {
public:
    struct HotKeyConfig {
        int toggleSkinKey = VK_INSERT;      // 切换皮肤显示
        int reloadConfigKey = VK_END;        // 重载配置
        int captureKey = VK_HOME;           // 截图
        int menuKey = VK_DELETE;             // 打开菜单
    };

private:
    HHOOK m_keyboardHook = nullptr;
    HHOOK m_mouseHook = nullptr;
    HMODULE m_interceptionDll = nullptr;
    std::atomic<bool> m_active{false};
    HotKeyConfig m_hotkeys;
    
    // Interception DLL 函数指针
    typedef void* (*InterceptionCreateContextFn)();
    typedef void (*InterceptionSetFilterFn)(void*, int);
    typedef int (*InterceptionReceiveFn)(void*, void*);
    typedef int (*InterceptionSendFn)(void*, void*);
    
    InterceptionCreateContextFn m_createContext = nullptr;
    InterceptionSetFilterFn m_setFilter = nullptr;
    InterceptionReceiveFn m_receive = nullptr;
    InterceptionSendFn m_send = nullptr;
    void* m_context = nullptr;
    
public:
    bool Initialize() {
        // 尝试加载 interception.dll
        std::wstring dllPath = g_app.appDataPath + L"drivers\\interception.dll";
        m_interceptionDll = LoadLibraryW(dllPath.c_str());
        
        if (!m_interceptionDll) {
            // 如果驱动 DLL 不在，使用 Windows hook
            return InitializeWindowsHook();
        }
        
        // 获取函数指针
        m_createContext = (InterceptionCreateContextFn)GetProcAddress(
            m_interceptionDll, "interception_create_context");
        m_setFilter = (InterceptionSetFilterFn)GetProcAddress(
            m_interceptionDll, "interception_set_filter");
        m_receive = (InterceptionReceiveFn)GetProcAddress(
            m_interceptionDll, "interception_receive");
        m_send = (InterceptionSendFn)GetProcAddress(
            m_interceptionDll, "interception_send");
            
        if (!m_createContext || !m_setFilter) {
            return InitializeWindowsHook();
        }
        
        // 创建拦截上下文
        m_context = m_createContext();
        if (!m_context) return false;
        
        // 设置过滤器: 拦截键盘和鼠标
        m_setFilter(m_context, 0x0700);  // KEYBOARD | MOUSE
        
        m_active = true;
        
        // 启动拦截线程
        std::thread(&InputInterceptor::InterceptionThread, this).detach();
        
        return true;
    }
    
    // Windows hook 备选方案 (LowLevelKeyboardHook + LowLevelMouseHook)
    bool InitializeWindowsHook() {
        m_keyboardHook = SetWindowsHookExW(
            WH_KEYBOARD_LL, KeyboardProc, g_app.hInstance, 0);
        
        m_mouseHook = SetWindowsHookExW(
            WH_MOUSE_LL, MouseProc, g_app.hInstance, 0);
        
        if (!m_keyboardHook || !m_mouseHook) return false;
        
        m_active = true;
        return true;
    }
    
    void Shutdown() {
        m_active = false;
        
        if (m_keyboardHook) {
            UnhookWindowsHookEx(m_keyboardHook);
            m_keyboardHook = nullptr;
        }
        if (m_mouseHook) {
            UnhookWindowsHookEx(m_mouseHook);
            m_mouseHook = nullptr;
        }
        
        if (m_context) {
            // interception_destroy_context(m_context);
            m_context = nullptr;
        }
        if (m_interceptionDll) {
            FreeLibrary(m_interceptionDll);
            m_interceptionDll = nullptr;
        }
    }
    
    void SetHotKeys(const HotKeyConfig& config) {
        m_hotkeys = config;
    }
    
    // 检查是否需要安装输入拦截驱动
    bool NeedsDriverInstall() {
        // 检查 interception.pending 文件
        std::wstring pendingPath = g_app.appDataPath + L"interception.pending";
        if (GetFileAttributesW(pendingPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;  // 有 pending 标记
        }
        return false;
    }
    
    // 安装输入拦截驱动 (install-interception.exe)
    bool InstallDriver() {
        std::wstring installerPath = g_app.appDataPath + L"drivers\\install-interception.exe";
        
        if (GetFileAttributesW(installerPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return false;
        }
        
        // 以管理员权限运行安装器
        SHELLEXECUTEINFOW sei = {};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        sei.lpVerb = L"runas";
        sei.lpFile = installerPath.c_str();
        sei.lpParameters = L"install";
        sei.nShow = SW_HIDE;
        
        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, 30000);  // 30s 超时
            CloseHandle(sei.hProcess);
            
            // 删除 pending 文件
            DeleteFileW((g_app.appDataPath + L"interception.pending").c_str());
            
            return true;
        }
        
        return false;
    }
    
private:
    // Interception 线程: 接收输入事件
    void InterceptionThread() {
        struct InterceptionStroke {
            BYTE data[256];
        };
        
        while (m_active && m_context) {
            InterceptionStroke stroke = {};
            int result = m_receive(m_context, &stroke);
            
            if (result > 0) {
                // 处理键盘/鼠标事件
                ProcessInputEvent(&stroke, result);
                
                // 转发到系统 (可选: 过滤特定按键)
                m_send(m_context, &stroke);
            }
        }
    }
    
    void ProcessInputEvent(void* stroke, int size) {
        // 检查热键
        BYTE* data = (BYTE*)stroke;
        
        // 解析按键
        if (size >= 4) {
            USHORT scanCode = *(USHORT*)(data);
            USHORT flags = *(USHORT*)(data + 2);
            bool isDown = !(flags & 0x01);  // KEY_DOWN
            
            if (isDown) {
                HandleHotKey(scanCode);
            }
        }
    }
    
    static LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
        if (code == HC_ACTION && wParam == WM_KEYDOWN) {
            KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;
            if (g_app.input) {
                g_app.input->HandleHotKey(kb->vkCode);
            }
        }
        return CallNextHookEx(nullptr, code, wParam, lParam);
    }
    
    static LRESULT CALLBACK MouseProc(int code, WPARAM wParam, LPARAM lParam) {
        if (code == HC_ACTION) {
            MSLLHOOKSTRUCT* ms = (MSLLHOOKSTRUCT*)lParam;
            // 处理鼠标事件 (皮肤交互)
        }
        return CallNextHookEx(nullptr, code, wParam, lParam);
    }
    
    void HandleHotKey(int vkCode) {
        if (vkCode == m_hotkeys.toggleSkinKey) {
            // 切换皮肤显示
            if (g_app.d3dHooks) {
                auto config = g_app.d3dHooks->m_config;  // 获取当前配置
                config.enabled = !config.enabled;
                g_app.d3dHooks->SetSkinConfig(config);
            }
        } else if (vkCode == m_hotkeys.reloadConfigKey) {
            // 重载云端配置
            if (g_app.config) {
                g_app.config->ReloadCloudConfig();
            }
        } else if (vkCode == m_hotkeys.captureKey) {
            // 截图
            CaptureScreen();
        } else if (vkCode == m_hotkeys.menuKey) {
            // 打开设置菜单
            if (g_app.ui) {
                g_app.ui->ShowSettingsMenu();
            }
        }
    }
    
    void CaptureScreen() {
        // 获取屏幕 DC
        HDC screenDC = GetDC(nullptr);
        HDC memDC = CreateCompatibleDC(screenDC);
        
        int w = GetSystemMetrics(SM_CXSCREEN);
        int h = GetSystemMetrics(SM_CYSCREEN);
        
        HBITMAP bmp = CreateCompatibleBitmap(screenDC, w, h);
        SelectObject(memDC, bmp);
        BitBlt(memDC, 0, 0, w, h, screenDC, 0, 0, SRCCOPY);
        
        // 保存到文件
        // ... PNG/JPEG 编码
        
        DeleteObject(bmp);
        DeleteDC(memDC);
        ReleaseDC(nullptr, screenDC);
    }
};
