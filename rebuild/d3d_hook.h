// ============================================================================
// AxonSkin v4.1 - D3D 渲染覆盖层 (游戏皮肤注入)
// 导入: d3d9.dll, d3d11.dll, d3d12.dll, dxgi.dll, DWrite.dll, dwmapi.dll
// 功能: 在游戏窗口上绘制皮肤覆盖层 (文字/图像/特效)
// ============================================================================

#pragma once
#include "common.h"
#include <d3d9.h>
#include <d3d11.h>
#include <dxgi.h>
#include <dwrite.h>
#include <dwmapi.h>
#include <d2d1.h>
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "dwmapi.lib")

// D3D Hook: 通过 vtable patch 拦截 Present/Reset
// 在游戏 Present 调用时注入皮肤渲染
class D3DHookManager {
public:
    struct SkinConfig {
        bool enabled = true;
        std::wstring text = L"Axon Skin";       // 覆盖文字
        uint32_t textColor = 0xFFFFFFFF;        // RGBA
        float fontSize = 16.0f;
        float opacity = 0.8f;
        float x = 10.0f, y = 10.0f;             // 位置
        bool showFPS = false;
        bool showTimer = false;
    };

private:
    // D3D9 vtable hook
    struct D3D9Hook {
        IDirect3DDevice9* device = nullptr;
        void* originalPresent = nullptr;
        void* originalReset = nullptr;
        bool hooked = false;
    };
    
    // D3D11 vtable hook  
    struct D3D11Hook {
        ID3D11Device* device = nullptr;
        IDXGISwapChain* swapChain = nullptr;
        void* originalPresent = nullptr;
        void* originalResizeBuffers = nullptr;
        bool hooked = false;
    };
    
    std::vector<D3D9Hook> m_d3d9Hooks;
    std::vector<D3D11Hook> m_d3d11Hooks;
    SkinConfig m_config;
    
    // DWrite 文字渲染
    IDWriteFactory* m_dwriteFactory = nullptr;
    IDWriteTextFormat* m_textFormat = nullptr;
    
public:
    bool Initialize() {
        // 初始化 DWrite
        HRESULT hr = DWriteCreateFactory(
            DWRITE_FACTORY_TYPE_SHARED,
            __uuidof(IDWriteFactory),
            reinterpret_cast<IUnknown**>(&m_dwriteFactory));
        
        if (SUCCEEDED(hr)) {
            m_dwriteFactory->CreateTextFormat(
                L"Microsoft YaHei UI",
                nullptr,
                DWRITE_FONT_WEIGHT_NORMAL,
                DWRITE_FONT_STYLE_NORMAL,
                DWRITE_FONT_STRETCH_NORMAL,
                m_config.fontSize,
                L"zh-CN",
                &m_textFormat);
        }
        
        return true;
    }
    
    // 扫描所有窗口，查找 D3D9/D3D11 设备
    void ScanAndHook() {
        // 枚举所有窗口
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto self = reinterpret_cast<D3DHookManager*>(lParam);
            
            wchar_t title[256];
            GetWindowTextW(hwnd, title, 256);
            if (GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;
            if (!IsWindowVisible(hwnd)) return TRUE;
            
            // 尝试 D3D9 hook
            self->TryHookD3D9(hwnd);
            // 尝试 D3D11 hook
            self->TryHookD3D11(hwnd);
            
            return TRUE;
        }, reinterpret_cast<LPARAM>(this));
    }
    
    // D3D9 设备创建 + vtable hook
    bool TryHookD3D9(HWND targetWnd) {
        // 创建临时 D3D9 设备获取 vtable
        IDirect3D9* d3d9 = Direct3DCreate9(D3D_SDK_VERSION);
        if (!d3d9) return false;
        
        D3DPRESENT_PARAMETERS pp = {};
        pp.Windowed = TRUE;
        pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
        pp.BackBufferFormat = D3DFMT_UNKNOWN;
        
        IDirect3DDevice9* device = nullptr;
        HRESULT hr = d3d9->CreateDevice(
            D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, targetWnd,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &device);
        
        d3d9->Release();
        
        if (FAILED(hr) || !device) return false;
        
        // 获取 vtable
        void** vtable = *reinterpret_cast<void***>(device);
        
        // vtable[17] = Present, vtable[16] = Reset
        void* presentAddr = vtable[17];
        void* resetAddr = vtable[16];
        
        // 保存原始函数指针
        D3D9Hook hook;
        hook.device = device;
        hook.originalPresent = presentAddr;
        hook.originalReset = resetAddr;
        
        // Patch vtable: 替换 Present 为我们的 hook
        DWORD oldProtect;
        VirtualProtect(&vtable[17], sizeof(void*), PAGE_READWRITE, &oldProtect);
        vtable[17] = reinterpret_cast<void*>(&HookedD3D9Present);
        VirtualProtect(&vtable[17], sizeof(void*), oldProtect, &oldProtect);
        
        hook.hooked = true;
        m_d3d9Hooks.push_back(hook);
        
        return true;
    }
    
    // D3D11 设备创建 + vtable hook
    bool TryHookD3D11(HWND targetWnd) {
        // 创建临时 D3D11 设备获取 swap chain vtable
        DXGI_SWAP_CHAIN_DESC scd = {};
        scd.BufferCount = 1;
        scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        scd.OutputWindow = targetWnd;
        scd.SampleDesc.Count = 1;
        scd.Windowed = TRUE;
        
        ID3D11Device* device = nullptr;
        IDXGISwapChain* swapChain = nullptr;
        
        D3D_FEATURE_LEVEL featureLevel;
        HRESULT hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            nullptr, 0, D3D11_SDK_VERSION,
            &scd, &swapChain, &device, &featureLevel, nullptr);
        
        if (FAILED(hr)) return false;
        
        // 获取 swap chain vtable
        void** vtable = *reinterpret_cast<void***>(swapChain);
        
        // vtable[8] = Present, vtable[13] = ResizeBuffers
        void* presentAddr = vtable[8];
        void* resizeAddr = vtable[13];
        
        D3D11Hook hook;
        hook.device = device;
        hook.swapChain = swapChain;
        hook.originalPresent = presentAddr;
        hook.originalResizeBuffers = resizeAddr;
        
        // Patch Present
        DWORD oldProtect;
        VirtualProtect(&vtable[8], sizeof(void*), PAGE_READWRITE, &oldProtect);
        vtable[8] = reinterpret_cast<void*>(&HookedD3D11Present);
        VirtualProtect(&vtable[8], sizeof(void*), oldProtect, &oldProtect);
        
        hook.hooked = true;
        m_d3d11Hooks.push_back(hook);
        
        return true;
    }
    
    void SetSkinConfig(const SkinConfig& config) {
        m_config = config;
    }
    
    void Shutdown() {
        for (auto& h : m_d3d9Hooks) {
            if (h.device) h.device->Release();
        }
        for (auto& h : m_d3d11Hooks) {
            if (h.swapChain) h.swapChain->Release();
            if (h.device) h.device->Release();
        }
        if (m_textFormat) m_textFormat->Release();
        if (m_dwriteFactory) m_dwriteFactory->Release();
    }
    
private:
    // Hooked D3D9 Present: 在游戏渲染完成后绘制皮肤覆盖层
    static HRESULT STDMETHODCALLTYPE HookedD3D9Present(
        IDirect3DDevice9* device, 
        const RECT* srcRect, 
        const RECT* destRect, 
        HWND destWindowOverride, 
        const RGNDATA* dirtyRegion, 
        DWORD flags) {
        
        // 调用原始 Present
        HRESULT hr = OriginalD3D9Present(device, srcRect, destRect, 
                                          destWindowOverride, dirtyRegion, flags);
        
        // 绘制皮肤覆盖层
        RenderSkinOverlayD3D9(device);
        
        return hr;
    }
    
    static HRESULT STDMETHODCALLTYPE HookedD3D11Present(
        IDXGISwapChain* swapChain, 
        UINT syncInterval, 
        UINT flags) {
        
        HRESULT hr = OriginalD3D11Present(swapChain, syncInterval, flags);
        
        // 绘制皮肤覆盖层
        ID3D11Device* device = nullptr;
        swapChain->GetDevice(__uuidof(ID3D11Device), (void**)&device);
        if (device) {
            RenderSkinOverlayD3D11(device, swapChain);
            device->Release();
        }
        
        return hr;
    }
    
    // D3D9 皮肤渲染
    static void RenderSkinOverlayD3D9(IDirect3DDevice9* device) {
        auto& config = g_app.d3dHooks->m_config;
        if (!config.enabled) return;
        
        // 创建 D3D 字体
        D3D_FONT_DESC fontDesc = {};
        fontDesc.Height = (int)config.fontSize;
        fontDesc.Width = 0;
        fontDesc.Weight = FW_NORMAL;
        fontDesc.CharSet = DEFAULT_CHARSET;
        wcscpy_s(fontDesc.FaceName, L"Microsoft YaHei UI");
        
        // 使用 ID3DXFont 绘制文字
        // 实际实现使用 D3DXCreateFont + DrawText
        // 这里展示渲染流程
        
        // 开始场景
        device->BeginScene();
        
        // 设置渲染状态: 启用 alpha 混合
        device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
        device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
        device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
        
        // 绘制文字覆盖层
        // text, textColor, x, y, opacity
        // ...
        
        device->EndScene();
    }
    
    // D3D11 皮肤渲染
    static void RenderSkinOverlayD3D11(ID3D11Device* device, IDXGISwapChain* swapChain) {
        auto& config = g_app.d3dHooks->m_config;
        if (!config.enabled) return;
        
        // 获取 back buffer
        ID3D11RenderTargetView* rtv = nullptr;
        ID3D11Texture2D* backBuffer = nullptr;
        if (SUCCEEDED(swapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backBuffer))) {
            device->CreateRenderTargetView(backBuffer, nullptr, &rtv);
            backBuffer->Release();
        }
        
        if (!rtv) return;
        
        // 设置渲染目标
        device->OMSetRenderTargets(1, &rtv, nullptr);
        
        // 使用 D2D/DWrite 在 D3D11 表面上绘制文字
        // 实际实现: 创建 D2D surface on D3D11 texture
        // ...
        
        rtv->Release();
    }
    
    // 原始函数指针 (实际实现中通过 trampoline 调用)
    static HRESULT STDMETHODCALLTYPE OriginalD3D9Present(
        IDirect3DDevice9* device, const RECT* src, const RECT* dest,
        HWND wnd, const RGNDATA* dirty, DWORD flags) {
        // 在实际 hook 中，这里是通过 trampoline 跳转到原始函数
        return device->Present(src, dest, wnd, dirty, flags);
    }
    
    static HRESULT STDMETHODCALLTYPE OriginalD3D11Present(
        IDXGISwapChain* sc, UINT sync, UINT flags) {
        return sc->Present(sync, flags);
    }
    
    struct D3D_FONT_DESC {
        int Height, Width, Weight;
        BYTE CharSet;
        wchar_t FaceName[32];
    };
};
