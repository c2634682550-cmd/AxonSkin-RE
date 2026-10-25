// ============================================================================
// AxonSkin v4.1 - UI 管理器 (Qt 6.8.3 + WTL)
// RTTI 类: Dlg_Main, Dlg_Login, Dlg_RMBind, Dlg_OnlineClient
// 对话框资源: 0x66(登录), 0x6A(在线客户端), 0x6B(机器码绑定)
// ============================================================================

#pragma once
#include "common.h"
#include <commctrl.h>
#include <dwmapi.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")

class UIManager {
public:
    // 对话框资源 ID (来自 axonlogin.dll)
    enum DialogRes {
        DLG_LOGIN = 102,          // 0x66 - 登录主对话框
        DLG_ONLINE_CLIENT = 106,  // 0x6A - "在线客户端信息"
        DLG_RMBIND = 107,         // 0x6B - "已绑定机器码信息"
    };
    
    // 控件 ID (来自 sub_180006560)
    enum ControlId {
        IDC_CARD_KEY = 1000,      // 0x3E8 - 卡密输入框
        IDC_TRIAL_BTN = 1005,     // 0x3ED - 试用按钮
        IDC_OTHER_BTN = 1007,     // 0x3EF - 其他按钮
        IDC_LOGIN_BTN = 1010,     // 0x3F2 - 登录/激活按钮
    };

private:
    HWND m_hMainWindow = nullptr;
    HWND m_hLoginDialog = nullptr;
    std::wstring m_windowTitle = L"Axon Skin 内测v4.1";
    
public:
    bool Initialize() {
        InitCommonControls();
        
        // 注册窗口类
        WNDCLASSEXW wc = { sizeof(wc) };
        wc.lpfnWndProc = MainWndProc;
        wc.hInstance = g_app.hInstance;
        wc.lpszClassName = L"AxonSkinMain";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassExW(&wc);
        
        return true;
    }
    
    // 显示登录对话框 (Dlg_Login, 资源 0x66)
    bool ShowLoginDialog() {
        // 基于 axonlogin.dll sub_18000DB40:
        // DialogBoxParamW(hInstance, 0x66, GetActiveWindow(), DialogFunc, 0)
        
        // 使用自定义对话框 (因为原始资源在壳内)
        m_hLoginDialog = CreateLoginDialog();
        
        if (!m_hLoginDialog) return false;
        
        ShowWindow(m_hLoginDialog, SW_SHOW);
        UpdateWindow(m_hLoginDialog);
        
        // 消息循环
        MSG msg;
        while (GetMessageW(&msg, nullptr, 0, 0)) {
            if (!IsDialogMessageW(m_hLoginDialog, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        
        return true;
    }
    
    // 显示主程序窗口 (Dlg_Main)
    void ShowMainWindow() {
        m_hMainWindow = CreateWindowExW(
            0, L"AxonSkinMain", m_windowTitle.c_str(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
            nullptr, nullptr, g_app.hInstance, this);
        
        if (m_hMainWindow) {
            ShowWindow(m_hMainWindow, SW_SHOW);
            UpdateWindow(m_hMainWindow);
            
            // 消息循环
            MSG msg;
            while (GetMessageW(&msg, nullptr, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    
    void ShowSettingsMenu() {
        // 弹出设置菜单
        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, 1, L"皮肤设置");
        AppendMenuW(hMenu, MF_STRING, 2, L"云端配置");
        AppendMenuW(hMenu, MF_STRING, 3, L"输入拦截设置");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, 4, L"检查更新");
        AppendMenuW(hMenu, MF_STRING, 5, L"关于");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, 6, L"退出");
        
        POINT pt;
        GetCursorPos(&pt);
        TrackPopupMenu(hMenu, TPM_LEFTALIGN, pt.x, pt.y, 0, m_hMainWindow, nullptr);
        DestroyMenu(hMenu);
    }
    
    HWND GetMainWindow() const { return m_hMainWindow; }
    HWND GetLoginDialog() const { return m_hLoginDialog; }
    
private:
    // 创建登录对话框 (重建原始资源 0x66)
    HWND CreateLoginDialog() {
        // 原始对话框布局 (基于 parse_login_dialogs.py 分析):
        // - 卡密输入框 (IDC_CARD_KEY=1000)
        // - 试用按钮 (IDC_TRIAL_BTN=1005)
        // - 登录按钮 (IDC_LOGIN_BTN=1010)
        // - 其他按钮 (IDC_OTHER_BTN=1007)
        
        HWND hDlg = CreateWindowExW(
            WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
            L"#32770",  // 对话框类
            L"Axon Skin 登录",
            WS_VISIBLE | WS_CAPTION | WS_SYSMENU | DS_CENTER | DS_MODALFRAME,
            CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
            nullptr, nullptr, g_app.hInstance, nullptr);
        
        if (!hDlg) return nullptr;
        
        // 添加控件
        CreateWindowExW(0, L"STATIC", L"卡密:", 
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 20, 50, 20, hDlg, (HMENU)2000, g_app.hInstance, nullptr);
        
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_LEFT,
            70, 18, 310, 24, hDlg, (HMENU)IDC_CARD_KEY, g_app.hInstance, nullptr);
        
        CreateWindowExW(0, L"BUTTON", L"试用",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 60, 100, 35, hDlg, (HMENU)IDC_TRIAL_BTN, g_app.hInstance, nullptr);
        
        CreateWindowExW(0, L"BUTTON", L"登录/激活",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,
            150, 60, 100, 35, hDlg, (HMENU)IDC_LOGIN_BTN, g_app.hInstance, nullptr);
        
        CreateWindowExW(0, L"BUTTON", L"解绑机器码",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            280, 60, 100, 35, hDlg, (HMENU)IDC_OTHER_BTN, g_app.hInstance, nullptr);
        
        // 状态文本
        CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 110, 360, 40, hDlg, (HMENU)2001, g_app.hInstance, nullptr);
        
        // 设置字体
        HFONT hFont = CreateFontW(
            16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            L"Microsoft YaHei UI");
        
        EnumChildWindows(hDlg, [](HWND hChild, LPARAM lParam) -> BOOL {
            SendMessageW(hChild, WM_SETFONT, lParam, TRUE);
            return TRUE;
        }, (LPARAM)hFont);
        
        // 设置对话框过程
        SetWindowLongPtrW(hDlg, GWLP_WNDPROC, (LONG_PTR)LoginDlgProc);
        
        return hDlg;
    }
    
    // 登录对话框过程 (sub_18000E5A0 的重建)
    static LRESULT CALLBACK LoginDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
            case WM_COMMAND:
                switch (LOWORD(wParam)) {
                    case IDC_TRIAL_BTN: {  // 试用按钮
                        if (g_app.auth->TryTrialLogin()) {
                            EndDialog(hDlg, 1);
                            // 显示主窗口
                            g_app.ui->ShowMainWindow();
                        }
                        break;
                    }
                    case IDC_LOGIN_BTN: {  // 登录按钮
                        // 读取卡密
                        wchar_t cardKey[64] = {};
                        GetDlgItemTextW(hDlg, IDC_CARD_KEY, cardKey, 64);
                        
                        if (g_app.auth->TryCardKeyLogin(cardKey)) {
                            // 显示过期时间
                            auto& result = g_app.auth->GetResult();
                            if (!result.expiryTime.empty()) {
                                // "过期时间:%04d年%02d月%02d日 %02d时%02d分%02d秒"
                                std::wstring msg = L"过期时间: " + result.expiryTime;
                                SetDlgItemTextW(hDlg, 2001, msg.c_str());
                            }
                            
                            EndDialog(hDlg, 1);
                            g_app.ui->ShowMainWindow();
                        }
                        break;
                    }
                    case IDC_OTHER_BTN: {  // 解绑机器码
                        g_app.auth->UnbindMachine();
                        break;
                    }
                }
                break;
                
            case WM_CLOSE:
                PostQuitMessage(0);
                break;
        }
        
        return DefDlgProcW(hDlg, msg, wParam, lParam);
    }
    
    // 主窗口过程 (Dlg_Main 的重建)
    static LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        UIManager* self = nullptr;
        
        if (msg == WM_CREATE) {
            auto cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
            self = reinterpret_cast<UIManager*>(cs->lpCreateParams);
            SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)self);
        } else {
            self = reinterpret_cast<UIManager*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
        }
        
        switch (msg) {
            case WM_CREATE:
                // 启动 D3D hook 和输入拦截
                if (g_app.d3dHooks) {
                    g_app.d3dHooks->Initialize();
                    g_app.d3dHooks->ScanAndHook();
                }
                if (g_app.input) {
                    if (g_app.input->NeedsDriverInstall()) {
                        g_app.input->InstallDriver();
                    }
                    g_app.input->Initialize();
                }
                
                // 设置定时器: 定期检查配置更新
                SetTimer(hWnd, 1, 3600000, nullptr);  // 1小时
                break;
                
            case WM_TIMER:
                if (wParam == 1) {
                    // 定期下载云端配置
                    if (g_app.config) {
                        g_app.config->ReloadCloudConfig();
                    }
                    // 检查更新
                    if (g_app.updater) {
                        g_app.updater->CheckForUpdates();
                    }
                }
                break;
                
            case WM_COMMAND:
                switch (LOWORD(wParam)) {
                    case 1:  // 皮肤设置
                        MessageBoxW(hWnd, L"皮肤设置", L"设置", MB_OK);
                        break;
                    case 2:  // 云端配置
                        if (g_app.config) g_app.config->ReloadCloudConfig();
                        break;
                    case 3:  // 输入拦截设置
                        MessageBoxW(hWnd, L"输入拦截设置", L"设置", MB_OK);
                        break;
                    case 4:  // 检查更新
                        if (g_app.updater) g_app.updater->PromptUpdate();
                        break;
                    case 5:  // 关于
                        MessageBoxW(hWnd,
                            L"Axon Skin 内测v4.1\n"
                            L"Qt 6.8.3 + D3D9/11/12 + Interception\n"
                            L"Meridian Software © 2026",
                            L"关于", MB_ICONINFORMATION);
                        break;
                    case 6:  // 退出
                        DestroyWindow(hWnd);
                        break;
                }
                break;
                
            case WM_CLOSE:
                DestroyWindow(hWnd);
                break;
                
            case WM_DESTROY:
                g_app.running = false;
                PostQuitMessage(0);
                break;
        }
        
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
};
