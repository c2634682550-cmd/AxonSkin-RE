# AxonSkin v4.1 功能还原与重建

基于以下逆向数据还原所有功能：
- axonlogin.dll (完整反编译 1079 函数, 1.08MB 伪代码)
- auth.pcapng (认证协议数据包)
- axonlogin.dll .rdata 明文字符串 (1453 UTF-16LE)
- axon_inner.bin RTTI 类名 (Dlg_Main/Dlg_Login/Dlg_RMBind/Dlg_OnlineClient)
- .rr4 导入表 (58 DLL, API 名称列表)
- AppData\Axon\AxonSkin\ 运行时数据 (cloud-cfg.bin, local.json, drivers)

---

## 1. 认证系统 (axonlogin.dll)

### 1.1 登录流程

```cpp
// 基于 axonlogin.dll sub_18000DB40 反编译
class AuthSystem {
    // SP_Init_v2 导出函数 @ RVA 0x12720
    // 壳调用此函数初始化登录流程
    
    void Init() {
        // 1. COM 初始化
        CoInitialize(NULL);
        
        // 2. 创建 WTL 消息循环
        CMessageLoop* loop = new CMessageLoop();
        
        // 3. 显示主登录对话框 (资源 ID 0x66=102)
        //    DialogBoxParamW(hInstance, 0x66, GetActiveWindow(), DialogFunc, 0)
        DialogBox(hInstance, MAKEINTRESOURCE(102), GetActiveWindow(), DialogProc);
    }
    
    // DialogFunc @ sub_18000E5A0 - WM_COMMAND 处理器
    LRESULT DialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
            case WM_COMMAND:
                switch (LOWORD(wParam)) {
                    case 0x3ED:  // 1005 - 试用按钮
                        OnTrialClick(hDlg);
                        break;
                    case 0x3F2:  // 1010 - 登录/激活按钮
                        OnLoginClick(hDlg);
                        break;
                    case 0x3EF:  // 1007 - 其他按钮
                        OnOtherAction(hDlg);
                        break;
                }
                break;
        }
    }
};
```

### 1.2 试用流程 (sub_1800076D0)

```cpp
// 试用按钮 → 创建 Dlg_RMBind 对话框 (机器码绑定)
void OnTrialClick(HWND hDlg) {
    // 1. 读取机器码
    std::wstring machineId = GetMachineId();
    if (machineId.empty()) {
        MessageBoxW(hDlg, L"未绑定机器码", L"提示", MB_ICONERROR);
        return;
    }
    
    // 2. 创建 Dlg_RMBind 对话框 (资源 0x6B=107 "已绑定机器码信息")
    DialogBoxParamW(hInstance, MAKEINTRESOURCE(107), 
                    GetActiveWindow(), DialogFunc, 0);
}
```

### 1.3 卡密登录流程 (sub_180006560)

```cpp
// 登录/激活按钮 → 创建 Dlg_OnlineClient 对话框
void OnLoginClick(HWND hDlg) {
    // 1. 读取卡密输入框 (control ID 0x3E8=1000)
    //    SendMessageW(hCtrl, WM_GETTEXT, ...) 获取卡密文本
    std::wstring cardKey = GetDlgItemText(hDlg, 1000);
    
    // 2. 验证卡密长度 (32-40 字符)
    if (cardKey.length() < 32 || cardKey.length() > 40) {
        MessageBoxW(hDlg, L"卡密长度不符!", L"错误", MB_ICONERROR);
        return;
    }
    
    // 3. 创建 Dlg_OnlineClient 对话框 (资源 0x6A=106 "在线客户端信息")
    DialogBoxParamW(hInstance, MAKEINTRESOURCE(106),
                    GetActiveWindow(), DialogFunc, 0);
    
    // 4. 在线验证 (sub_180006560 case 1)
    //    调用 qword_180050B80 (主程序回调对象) 的虚函数 +0x90
    //    返回值 0=成功, 其他=错误码
    int result = OnlineAuth(cardKey, machineId);
    
    switch (result) {
        case 0:  // 成功
            // 显示过期时间: "过期时间:%04d年%02d月%02d日 %02d时%02d分%02d秒"
            ShowExpiryTime(hDlg);
            // 调用最终验证 sub_1800091D0
            FinalVerification(hDlg);
            EndDialog(hDlg, 1);  // 返回成功，壳开始解密
            break;
        case -4: MessageBoxW(hDlg, L"IP、机器码不符!", L"提示", MB_ICONWARNING); break;
        case -3: MessageBoxW(hDlg, L"该代理下所有卡密无法登录!", L"提示", MB_ICONWARNING); break;
        case -2: MessageBoxW(hDlg, L"但试用卡无法解绑!", L"提示", MB_ICONWARNING); break;
        // ... 更多错误码
    }
}
```

### 1.4 在线认证协议 (124.222.192.168:9486)

```python
# 基于 auth.pcapng 分析
import struct, socket

class AuthProtocol:
    SERVER = "124.222.192.168"
    PORT = 9486
    
    def auth_request(self, card_key: str, machine_id: str, version: int):
        """发送认证请求 (cmd=0x02)
        请求格式: 4字节长度 + 1字节命令 + 加密载荷
        请求大小: 45字节 (4 + 1 + 40)
        """
        # 构建载荷 (40字节)
        payload = self._encrypt_payload(card_key, machine_id, version)
        
        # 封包: length(4) + cmd(1) + payload(40)
        packet = struct.pack('<I', 1 + len(payload))  # length = cmd + payload
        packet += struct.pack('B', 0x02)  # cmd = 0x02 (auth request)
        packet += payload
        
        # 发送
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.SERVER, self.PORT))
        sock.sendall(packet)
        
        # 接收响应 (166字节)
        response = sock.recv(1024)
        sock.close()
        
        # 解析响应
        resp_len = struct.unpack('<I', response[:4])[0]  # 0xa6 = 166
        resp_data = response[4:]
        
        # 解密响应
        return self._decrypt_response(resp_data)
    
    def _encrypt_payload(self, card_key, machine_id, version):
        """加密载荷 — XOR 加密 (0x2f 字节频率最高)"""
        # 载荷结构: 卡密(32B) + 机器码(4B) + 版本号(4B)
        raw = card_key.encode('ascii')[:32]
        raw += machine_id.encode('ascii')[:4].ljust(4, b'\x00')
        raw += struct.pack('<I', version)
        
        # XOR 加密
        key = 0x2F  # XOR key (从字节频率分析推断)
        encrypted = bytes(b ^ key for b in raw)
        return encrypted.ljust(40, b'\x00')
```

### 1.5 最终验证 (sub_1800091D0)

```cpp
// 壳调用主程序的最终验证函数
// 通过 qword_180050B80 (主程序回调对象) 的虚函数表调用
void FinalVerification(void* authObj) {
    // 分配 3 个缓冲区
    char* buf1 = Alloc(2049);  // 认证响应数据
    char* buf2 = Alloc(101);   // 卡密/会话信息
    char* buf3 = Alloc(129);   // 机器码信息
    
    int result = 0;
    int version_required = 0;
    
    // 重试 3 次，每次间隔 300ms
    for (int i = 0; i < 3; i++) {
        // (qword_180050B80 + 0x90) = 主程序在线认证回调
        result = (*(authObj + 0x90))(&status, &version_required, &state2, buf1, buf2, buf3);
        if (result == 1) break;
        Sleep(300);  // 0x12C ms
    }
    
    // 释放缓冲区
    Free(buf1); Free(buf2); Free(buf3);
    
    // 验证条件
    if (result != 1 || 
        (version_required != 0 && currentVersion < version_required)) {
        // 失败: 显示错误消息 + 1200ms 等待 + ExitProcess(0)
        SetErrorText(authObj, "S_MR\rN/f", error_msg, 64);
        Sleep(1200);  // 0x4B0 ms
        ExitProcess(0);
    }
    // 成功: 函数返回，壳继续解密 .text
}
```

---

## 2. 机器码绑定/解绑 (Dlg_RMBind)

```cpp
class MachineBinding {
    // 试用次数管理
    int GetUnbindCount() {
        // 从注册表读取: HKEY_CURRENT_USER\Software\Axon\Skin
        // "unbind_count" 值
        return RegReadInt(HKCU, L"Software\\Axon\\Skin", L"unbind_count");
    }
    
    void ShowUnbindInfo() {
        int remaining = GetUnbindCount();
        if (remaining <= 0) {
            MessageBoxW(NULL, L"已达最多解绑次数, 无法解绑!", 
                        L"提示", MB_ICONWARNING);
            return;
        }
        
        // "本次解绑将消耗赠送的解绑次数(剩余: %d) 是否前往解绑页面?"
        wchar_t msg[256];
        swprintf(msg, L"本次解绑将消耗赠送的解绑次数(剩余: %d) 是否前往解绑页面?", remaining);
        
        if (MessageBoxW(NULL, msg, L"提示", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            // 打开解绑页面
            ShellExecuteW(NULL, L"open", L"explorer.exe", 
                          L"https://wwaoo.lanzoue.com/s/daozidan", NULL, SW_SHOW);
        }
    }
    
    void UnbindMachine() {
        // "本次解绑不扣除时长! %s 内剩余解绑次数: %d (含本次)"
        // 解绑后更新注册表
        RegWriteInt(HKCU, L"Software\\Axon\\Skin", L"unbind_count", 
                    GetUnbindCount() - 1);
    }
};
```

---

## 3. 版本更新系统

```cpp
class UpdateSystem {
    // 基于 axonlogin.dll .rdata 字符串
    void CheckVersion() {
        // "当前不是最新版本，点击[确定]前往下载最新版本！"
        if (!IsLatestVersion()) {
            if (MessageBoxW(NULL, 
                L"当前不是最新版本，点击[确定]前往下载最新版本！",
                L"版本更新", MB_OKCANCEL | MB_ICONINFORMATION) == IDOK) {
                // 下载地址: https://wwaoo.lanzoue.com/s/daozidan
                ShellExecuteW(NULL, L"open", 
                    L"https://wwaoo.lanzoue.com/s/daozidan", NULL, NULL, SW_SHOW);
            }
        }
    }
    
    void DownloadUpdate() {
        // WinINet HTTP 下载
        // User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36...
        // Accept: */*
        // Accept-Language: zh-cn
        // Accept-Encoding: no-gzip, deflate
        
        HINTERNET hSession = InternetOpenW(
            L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36...",
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        
        HINTERNET hUrl = InternetOpenUrlW(hSession,
            L"https://wwaoo.lanzoue.com/s/daozidan",
            L"Accept: */*\r\nAccept-Language: zh-cn\r\nAccept-Encoding: no-gzip, deflate\r\n",
            0, INTERNET_FLAG_RELOAD, 0);
        
        // 下载进度: "Download progress"
        // 解压进度: "Decompression progress"
        // "The update package download is complete .."
        // "Extracting update package .."
        // "Update package decompression completed .."
        // "Starting the main program .."
        // "The upgrade program is about to exit .."
    }
};
```

---

## 4. 主程序功能 (基于 RTTI + 导入表 + AppData)

### 4.1 对话框类结构

```cpp
// RTTI from axon_inner.bin
class Dlg_Main;        // 主程序对话框
class Dlg_Login;       // 登录对话框 (资源 0x66)
class Dlg_RMBind;      // 机器码绑定对话框 (资源 0x6B)
class Dlg_OnlineClient;// 在线客户端信息 (资源 0x6A)

// 模板: CUpdateUI<VDlg_*>
template<typename TDlg>
class CUpdateUI : public CWindowImpl<CUpdateUI<TDlg>> {
    // UI 更新处理器
};
```

### 4.2 依赖库 (58 DLL)

```
系统: kernel32, user32, gdi32, advapi32, shell32, ole32, comctl32, comdlg32
图形: d3d9, d3d11, d3d12, dxgi, gdiplus, dwrite, dwmapi, uxtheme
网络: winhttp, ws2_32, dnsapi, iphlpapi, secur32, ncrypt, bcrypt, crypt32
输入: imm32, uiautomationcore, winmm
系统信息: setupapi, wtsapi32, userenv, shlwapi, version, netapi32, authz
C++: msvcp140, msvcp140_1, msvcp140_2, vcruntime140, vcruntime140_1, concrt140
CRT: api-ms-win-crt-* (convert, environment, filesystem, heap, locale, math, runtime, stdio, string, time, utility)
```

### 4.3 关键 API (动态解析)

```cpp
// 从 .rr4 导入表
// 反调试
IsDebuggerPresent();
OutputDebugStringW();

// 内存操作 (壳自解密)
VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
VirtualFree(addr, 0, MEM_RELEASE);

// 异常处理 (用于反调试和 VM)
RtlLookupFunctionEntry();
RtlVirtualUnwind();

// 网络
InternetGetConnectedState();
InternetOpenW();
InternetOpenUrlW();
InternetReadFile();
InternetCloseHandle();

// 注册表操作
RegOpenKeyExW();
RegCreateKeyExW();
RegSetValueExW();
RegDeleteKeyW();
RegQueryValueExW();
RegEnumKeyExW();
RegCloseKey();
// 事务操作 (原子性)
RegOpenKeyTransactedW();
RegCreateKeyTransactedW();
RegDeleteKeyTransactedW();
```

### 4.4 配置文件系统

```cpp
// AppData\Axon\AxonSkin\
class ConfigSystem {
    std::string appDataPath = "%APPDATA%\\Axon\\AxonSkin\\";
    
    // local.json: {"version":4}
    void LoadLocalConfig() {
        json config = json::parse(ReadFile("local.json"));
        int version = config["version"];  // 4
    }
    
    // cache\cloud-cfg.bin (1.77KB, 加密配置)
    // 使用主程序的解密函数 (VirtualProtect + XOR 解密)
    void LoadCloudConfig() {
        std::vector<uint8_t> data = ReadFile("cache\\cloud-cfg.bin");
        // 解密: 主程序虚函数调用 (同 sub_180005890 路径)
        Decrypt(data);  // 需要 DLL 的解密函数
    }
    
    // interception.pending: Unix 时间戳 (毫秒)
    // 1792701781136 → 2026-10-25
    // 输入拦截驱动安装时间
    void CheckInterceptionDriver() {
        if (FileExists("drivers\\interception.dll")) {
            // 安装输入拦截驱动
            // drivers\install-interception.exe (459KB)
            // drivers\interception.dll (11KB)
        }
    }
};
```

### 4.5 输入拦截系统

```cpp
// 基于 AppData\Axon\AxonSkin\drivers\
// interception = 键盘/鼠标输入拦截 (游戏皮肤注入需要)
class InputInterception {
    void Install() {
        // 1. 运行 install-interception.exe
        // 2. 加载 interception.dll 到目标进程
        // 3. 拦截输入设备 (键盘/鼠标) 实现皮肤热键
        
        // interception.pending 时间戳: 驱动安装计划时间
        WriteFile("interception.pending", 
                  std::to_string(GetCurrentTimeMs()));
    }
    
    void Hook() {
        // 使用 SetWindowsHookEx 或 DLL 注入
        // 拦截 WH_KEYBOARD_LL 和 WH_MOUSE_LL
    }
};
```

---

## 5. 版本信息

```
目标 EXE:
  CompanyName: Axon Studio
  ProductName: DeskHelper.exe
  FileDescription: Axon Skin 内测v4.1

登录 DLL (axonlogin.dll):
  CompanyName: Meridian Software
  ProductName: Meridian Runtime
  FileDescription: Runtime UI Module
  Copyright: Copyright (C) 2026
  Version: 1.0.0.0
```

---

## 6. SProtect 壳机制总结

```
1. 启动: requireAdministrator → 提权
2. 反调试: 窗口标题扫描 (IDA/逆向/AxonSkin/dbg) + PEB + IsDebuggerPresent
3. SP_Init_v2: 加载 axonlogin.dll → 显示登录对话框
4. 登录成功 → 调用 sub_1800091D0 (在线验证) → 主程序回调
5. 验证成功 → SProtect 解密 .text (但使用 VM 虚拟化执行)
6. VM 解释器: .a1 + .rr4 中的混淆代码 = VM bytecode interpreter
7. 真实代码从未以原生 x86-64 形式存在于内存中
8. 程序功能完全通过 VM 解释执行
```
