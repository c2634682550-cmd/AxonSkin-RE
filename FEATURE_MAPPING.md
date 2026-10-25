# AxonSkin v4.1 功能还原对照表

## 目标
逆向 `AxonSkin v4.1.exe` (168MB, SProtect 壳) → 提取全部功能 → 用干净 C++ 代码重建

## 逆向数据来源

| 数据源 | 大小 | 用途 |
|--------|------|------|
| axonlogin.dll 完整反编译 | 1079 函数, 1.08MB 伪代码 | 登录/认证/试用/解绑/更新 |
| axon_inner.bin 反编译 | 777 函数, 970KB | RTTI 类名 (4 个 Dlg 类) |
| .a1 代码区分析 | 13805 函数 (VM 虚拟化) | 确认 SProtect VM 架构 |
| .rr4 导入表 | 58 DLL, 24MB | 完整运行时依赖图 |
| auth.pcapng | 认证协议数据包 | TCP 124.222.192.168:9486 |
| 崩溃日志 JSON | 2 份 (v2.3/v4.1) | 系统信息/显示/CPU/内存/Qt版本 |
| 崩溃 minidump | 4 份 | 105 个加载模块 |
| AppData\Axon\AxonSkin\ | local.json, cloud-cfg.bin, interception.pending, drivers\ | 配置/缓存/驱动 |

## 功能 → 重建代码对照

### 1. 认证系统
| 原始函数 | RVA | 重建位置 | 功能 |
|----------|-----|----------|------|
| SP_Init_v2 | 0x12720 | main.cpp: wWinMain | 壳初始化 → 显示登录对话框 |
| sub_18000DB40 | - | ui.h: ShowLoginDialog | 创建 Dlg_Login (0x66) |
| DialogFunc | 0xE5A0 | ui.h: LoginDlgProc | WM_COMMAND 处理器 |
| sub_1800076D0 (试用) | 0x76D0 | auth.h: TryTrialLogin | Dlg_RMBind (0x6B) |
| sub_180006560 (登录) | 0x6560 | auth.h: TryCardKeyLogin | Dlg_OnlineClient (0x6A) |
| sub_1800091D0 (验证) | 0x91D0 | auth.h: FinalVerification | 3 次重试 + 版本检查 |
| 在线认证 | - | auth.h: SendAuthRequest | TCP 124.222.192.168:9486 |

### 2. 机器码系统
| 功能 | 原始来源 | 重建位置 |
|------|----------|----------|
| 机器码生成 | axonlogin.dll | auth.h: GetMachineId |
| 解绑次数管理 | 注册表 HKCU\Software\Axon\Skin | auth.h: ReadUnbindCount/WriteUnbindCount |
| 试用次数管理 | 注册表 | auth.h: ReadTrialCount/WriteTrialCount |

### 3. D3D 渲染覆盖层 (游戏皮肤)
| 功能 | 导入来源 | 重建位置 |
|------|----------|----------|
| D3D9 Present Hook | d3d9.dll | d3d_hook.h: TryHookD3D9 |
| D3D11 Present Hook | d3d11.dll | d3d_hook.h: TryHookD3D11 |
| 文字渲染 | DWrite.dll | d3d_hook.h: DWriteFactory |
| 皮肤配置 | cloud-cfg.bin | d3d_hook.h: SkinConfig |
| Alpha 混合 | d3d9/d3d11 | d3d_hook.h: RenderSkinOverlay |

### 4. 输入拦截 (皮肤热键)
| 功能 | 数据来源 | 重建位置 |
|------|----------|----------|
| Interception 驱动 | AppData\drivers\interception.dll | input_hook.h: Initialize |
| 驱动安装 | AppData\drivers\install-interception.exe | input_hook.h: InstallDriver |
| 键盘 Hook | WH_KEYBOARD_LL | input_hook.h: KeyboardProc |
| 鼠标 Hook | WH_MOUSE_LL | input_hook.h: MouseProc |
| 热键配置 | (推断) | input_hook.h: HotKeyConfig |
| 截图功能 | (推断) | input_hook.h: CaptureScreen |

### 5. 配置系统
| 功能 | 数据来源 | 重建位置 |
|------|----------|----------|
| 本地配置 | AppData\local.json | config.h: LoadLocalConfig |
| 云端配置 | AppData\cache\cloud-cfg.bin | config.h: LoadCloudConfigCache |
| 云端配置下载 | winhttp.dll | config.h: DownloadCloudConfig |
| 云端配置解密 | cloud-cfg.bin (1814B 加密) | config.h: DecryptCloudConfig |
| 控制台固定 | local.json: consolePinDone | config.h: SetConsolePinDone |

### 6. 版本更新
| 功能 | 字符串来源 | 重建位置 |
|------|----------|----------|
| 检查更新 | "当前不是最新版本" | update.h: CheckForUpdates |
| 下载页面 | wwaoo.lanzoue.com/s/daozidan | update.h: PromptUpdate |
| 下载更新包 | "Download progress" | update.h: DownloadFile |
| 解压更新包 | "Extracting update package" | update.h: ExtractArchive |
| 替换主程序 | "Starting the main program" | update.h: DownloadAndInstall |

### 7. 崩溃处理
| 功能 | 数据来源 | 重建位置 |
|------|----------|----------|
| SEH 异常捕获 | crash-*.json: kind=SEH | crash.h: UnhandledExceptionFilter |
| Minidump 生成 | *.dmp (MiniDumpWriteDump) | crash.h: WriteMinidump |
| 崩溃 JSON 报告 | crash-*.json 格式 | crash.h: WriteCrashJSON |
| 系统信息收集 | crash JSON system 字段 | crash.h: CollectSystemInfo |
| 显示器信息 | crash JSON displays 字段 | crash.h: CollectDisplayInfo |

### 8. UI 系统
| 功能 | RTTI 来源 | 重建位置 |
|------|----------|----------|
| 登录对话框 | Dlg_Login (0x66) | ui.h: CreateLoginDialog |
| 机器码绑定对话框 | Dlg_RMBind (0x6B) | ui.h: LoginDlgProc |
| 在线客户端信息 | Dlg_OnlineClient (0x6A) | ui.h: ShowSettingsMenu |
| 主程序窗口 | Dlg_Main | ui.h: ShowMainWindow |
| 窗口标题 | "Axon Skin 内测v4.1" | ui.h: m_windowTitle |

### 9. 反调试 (参考)
| 功能 | 来源 | 重建位置 |
|------|------|----------|
| 窗口标题扫描 | SProtect 壳 | main.cpp: AntiDebugBypass |
| 检测关键词 | IDA/逆向/dbg | main.cpp: CheckDebuggerWindow |
| 拒绝消息 | "禁止调试软件" | main.cpp: ShowAntiDebugWarning |

## 重建文件列表

| 文件 | 行数 | 功能 |
|------|------|------|
| common.h | 116 | 全局上下文/工具函数 |
| auth.h | 394 | 认证系统 (登录/试用/解绑/TCP协议) |
| config.h | 234 | 配置系统 (本地/云端/解密) |
| d3d_hook.h | 314 | D3D 渲染覆盖层 (D3D9/11 Hook) |
| input_hook.h | 250 | 输入拦截 (Interception/WH_HOOK) |
| update.h | 250 | 版本更新 (检查/下载/安装) |
| crash.h | 414 | 崩溃处理 (SEH/Dump/JSON) |
| ui.h | 297 | UI 管理 (对话框/窗口/菜单) |
| main.cpp | 147 | 程序入口/初始化/消息循环 |
| CMakeLists.txt | - | 构建配置 (58 库链接) |
| **合计** | **2416 行** | **完整功能覆盖** |

## 运行时依赖 (105 模块)

### 核心 DLL (58 个直接导入)
d3d9, d3d11, D3D12, dxgi, DWrite, dwmapi, uxtheme, GdiPlus, 
winhttp, ws2_32, dnsapi, iphlpapi, secur32, ncrypt, bcrypt, crypt32,
imm32, winmm, setupapi, wtsapi32, userenv, shlwapi, version, netapi32, authz,
msvcp140, msvcp140_1, msvcp140_2, vcruntime140, vcruntime140_1, concrt140,
kernel32, user32, gdi32, advapi32, shell32, ole32, oleaut32, comctl32, comdlg32,
shcore, dbghelp, combase, rpcrt4, schannel, wintrust, mswsock, clbcatq,
Windows.UI, Windows.UI.Immersive, CoreMessaging, CoreUIComponents, textinputframework,
TextShaping, dataexchange, UIAutomationCore, twinapi.appcore, msi, atlthunk

### Qt 6.8.3 (静态链接)
- Qt 的所有模块被静态链接到 EXE 内部 (无外部 Qt DLL)
- 崩溃日志确认: `"qt": "6.8.3"`

### 拦截驱动
- interception.dll (11KB) — 输入拦截核心
- install-interception.exe (459KB) — 驱动安装器

## SProtect 壳机制

1. `requireAdministrator` manifest → 提权启动
2. 窗口标题扫描 → 反调试检测
3. SP_Init_v2 → 加载 axonlogin.dll → 显示登录
4. 登录成功 → sub_1800091D0 在线验证 → 主程序回调
5. 验证成功 → SProtect VM 解密执行
6. 代码虚拟化: .text 全零, VM bytecode 在 .a1/.rr4
7. 13805 个 VM 函数 = 控制流混淆 (movabs/xchg/xor/rol/not)
8. 真实代码从未以原生 x86-64 存在内存

## 认证协议细节

- 服务器: 124.222.192.168:9486 (腾讯云)
- 协议: 自定义 TCP
- 请求: 4B length + 1B cmd + 40B XOR加密载荷
- 响应: 166B (4B length + 162B XOR加密数据)
- 命令: 0x01=试用, 0x02=认证, 0x03=解绑
- XOR Key: 0x2F
- 载荷: 卡密(32B) + 机器码Hash(4B) + 版本号(4B)
- 响应: status(1B) + errorCode(1B) + expiryTime(20B) + remainingDays(4B) + unbindCount(4B)
