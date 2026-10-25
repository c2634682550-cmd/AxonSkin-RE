# AxonSkin v4.1 逆向分析报告

## 目标信息
- **文件**: `C:\Users\26346\Downloads\AxonSkin v4.1.exe` (168,471,040 bytes / 160MB)
- **SHA256**: `2b64218080ba7a2ace54e254388a623d4bfa0e0f38fe466fde5df55333652ffb`
- **OriginalFilename**: `DeskHelper.exe` (FileDescription: "Desktop Helper")
- **CompanyName**: Axon Studio, Version 3.0.0.0
- **框架**: Qt 6.8.3, x64 GUI PE
- **壳**: SProtect custom packer (非标准 MPRESS)

## PE 结构
| 节名 | RVA | VirtualSize | RawSize | 说明 |
|------|-----|-------------|--------|------|
| .text | 0x1000 | 0x26092cd (38MB) | 0 | 主程序代码，运行时解密 |
| .rdata | 0x260b000 | 0x15eaad4 | 0 | 只读数据，运行时填充 |
| .data | 0x3bf6000 | 0x10c698 | 0 | 全局数据 |
| .pdata | 0x3d03000 | 0x1bb1b4 | 0 | 异常处理表 |
| .qtmimed | 0x3ebf000 | 0xb0e9 | 0 | Qt MIME 数据 |
| .s0w | 0x3ecc000 | 0x1df7000 (30MB) | 0x1df7000 | 壳加密数据 |
| .xwkeh | 0x5cc4000 | 0x70f0000 (112MB) | 0 | 壳加密载荷 |
| .jgaz | 0xcdb4000 | 0x80d0000 | 0x80cfa00 | 壳加密载荷 |
| .rsrc | 0x14e84000 | 0x26000 | 0x26000 | 资源 (manifest, icon) |
| .reloc | 0x14eaa000 | 0x1f000 | 0x1f000 | 重定位 |

**关键**: .text/.rdata/.data 的 RawSize=0 — 壳在运行时解密填充这些节。

## SProtect 壳分析

### 入口点
- EP RVA: `0x13fee150` (在 .rr4 节内)
- EP 处: `jmp 0x154e9f1e6` → jo/jno 跳板链 → 壳 stub 主体
- 壳 stub 代码在 .rr4/.s0w 节，运行时自解密

### 反调试机制
1. **窗口标题扫描**: 扫描所有窗口标题，匹配关键词列表:
   - IDA, 逆向, AxonSkin, dbg, debugger, 等
   - 命中后弹 MessageBox: "禁止调试软件, 请关闭调试器然后重新运行!"
   - **绕过**: rename_windows.py 重命名匹配窗口标题

2. **PEB 访问混淆**: 3 处 `mov rax, gs:[0x60]` (PEB 访问)
   - 每处用 movabs/xchg/sub/xor/rol/not + ret 做控制流虚拟化
   - 计算 `0x7ff64e700000` 基址偏移

3. **API 动态解析**: 壳不使用正常 IAT
   - 58 个导入 DLL，每个只导入 1 个符号（壳 IAT 混淆）
   - 运行时通过 PEB→Ldr 遍历 + 名称哈希解析真实 API

4. **提权要求**: manifest `requireAdministrator`
   - **绕过**: patch_manifest2.py 重写为 `asInvoker`

### 解密触发
- .text (38MB 真实代码) **仅在用户通过登录验证后解密**
- 壳加载阶段 .text 全零；登录成功后壳解密 .text 并跳转到真实 EP

## 登录系统 (axonlogin.dll)

### 文件信息
- **路径**: `%TEMP%\axonlogin.dll` (548,864 bytes / 536KB)
- **导出**: `SP_Init_v2` (RVA 0x12720) — 壳调用的初始化入口
- **编译器**: MSVC v14 (x64), 静态链接 CRT + boost::asio + WTL
- **节**: .text(214KB) .rdata .data .pdata .fptable .rsrc .reloc

### SP_Init_v2 流程
```
SP_Init_v2(moduleHandle)
  → 保存模块句柄到 qword_180050B80
  → GetModuleFileNameA 获取宿主 exe 路径
  → sub_18000DB40()  // 真正初始化
```

### sub_18000DB40 (登录初始化)
```
1. CoInitialize(nullptr)              // COM 初始化
2. InitCommonControlsEx              // 通用控件
3. WTL::CMessageLoop 消息循环设置
4. GetActiveWindow()                // 获取父窗口
5. sub_180012B74()                  // 创建登录管理器对象
6. DialogBoxParamW(hInstance, 0x66, parentWnd, DialogFunc, 0)
   // 弹出登录对话框 (资源 ID 0x66 = 102)
```

### 登录对话框 (ID 0x66)
**控件 ID 映射** (通过 GetDlgItem 获取):
| 控件 ID | 用途 |
|---------|------|
| 1002 (0x3EA) | 标签/说明文本 |
| 1005 (0x3ED) | "试用"按钮 |
| 1006 (0x3EE) | 输入框1 (卡密) |
| 1007 (0x3EF) | 按钮3 (可能"购买") |
| 1008 (0x3F0) | 输入框2 |
| 1009 (0x3F1) | 隐藏控件 |
| 1010 (0x3F2) | "登录/激活"按钮 |

### WM_COMMAND 处理 (sub_18000E5A0)
```
case 0x3ED (1005): sub_1800076D0()   // 试用按钮
case 0x3F2 (1010): sub_180006560()   // 登录/激活按钮
case 0x3EF (1007): sub_180006EB0()   // 按钮3
case 2:            sub_180005A40()   // 取消
```

### 试用按钮 (sub_1800076D0)
- 创建 `Dlg_RMBind` 对话框 (机器码绑定)
- 读取注册表试用状态
- 试用为一次性: 首次试用后写入注册表标记，后续不再显示试用按钮

### 登录/激活按钮 (sub_180006560, 2384字节)
- 创建 `Dlg_OnlineClient` 对话框 (在线验证)
- 读取卡密输入: SendMessageW(a1[20], 0xF0) + SendMessageW(a1[19], 0xF0)
  - a1[19] = 卡密输入框
  - a1[20] = 验证码/辅助输入框
- 卡密长度检查: 需在 32-40 字符之间
- 调用 `qword_180050B80` (主程序回调函数) 传入卡密进行验证
- SYSTEMTIME 结构用于到期时间计算
- 验证成功 → EndDialog(1) → 壳解密 .text → 跳转真实 EP

## 验证协议 (auth.pcapng)

### 服务器
- **IP**: `124.222.192.168`
- **端口**: `9486`
- **协议**: TCP, 自定义二进制协议

### 请求包结构 (客户端→服务器, 45 bytes)
```
偏移  长度  值          说明
0     4    0x2D000000   包长度 (45)
4     1    0x02         命令类型 (认证请求)
5     40   加密数据     XOR 加密的认证载荷
```

**加密载荷** (XOR 加密, 0x2f 为密钥特征字节):
```
请求1: 08372b4109d8e2f4f2b0cdf4c9cf2f01890f4f01d92f030199622f01992f1fd5d52f85166c91b5a4
请求2: 7603439509d8e2f4f2b0cdf4c9cf2f01090f4f01d92f030199622f01992f3f66d12f8416fce0b5a4
```
- 末尾 4 字节 `b5a4` = 校验/签名
- 中间数据含: HWID(机器码)、卡密、版本号

### 响应包结构 (服务器→客户端)
```
响应1 (166 bytes): a6000000 eba843de ... 4c425f484923fd5968c67fe9b5a4
  - 0x166 = 包长度 (166)
  - 加密的授权结果: VIP状态、到期时间、功能权限

响应2 (36 bytes): 24000000 2f6742ea ... 5959485f91ea1901b9e8
  - 0x24 = 包长度 (36)
  - 简短确认
```

### 重传
- 每个请求重传 7 次 (TCP 层), 每个响应重传 5 次
- 表明壳的网络层有重试机制

## 配置文件

### local.json
```json
{ "version": 4 }  // 配置版本
```

### cloud-cfg.bin (1,814 bytes)
- 加密的云端配置
- XOR 单字节密钥无法解密（需要 DLL 中的解密函数）
- 可能含: 服务器地址、端口、功能开关、公告文本

### interception.pending
```
1792701781136  // Unix 时间戳 → 2026-10-25 (输入拦截驱动安装待定)
```

## 释放文件

| 文件 | 大小 | 说明 |
|------|------|------|
| %TEMP%\axon.exe | 166MB | 壳释放的主程序载荷 (与 axon_target.exe 相同) |
| %TEMP%\axon_target.exe | 166MB | 主程序载荷副本 |
| %TEMP%\axonlogin.dll | 536KB | **登录 DLL (明文, 已完整反编译)** |
| %TEMP%\axon_inner.bin | 552KB | 内部 PE (明文, 含壳的内部逻辑) |
| %TEMP%\axon_bin_res.bin | 203KB | 二进制资源 PE (明文) |
| %TEMP%\axon_auth\auth.pcapng | 11.6KB | **登录网络流量抓包** |
| %TEMP%\axon_auth\auth.etl | 35.7KB | ETW 跟踪日志 |
| %TEMP%\axon_regions\ | - | 壳自转储的内存镜像 (560 个区域) |
| %APPDATA%\Axon\AxonSkin\cache\cloud-cfg.bin | 1.8KB | 加密的云端配置 |
| %APPDATA%\Axon\AxonSkin\local.json | - | 本地配置 |
| %APPDATA%\Axon\AxonSkin\drivers\interception.dll | 11KB | 输入拦截驱动 DLL |
| %APPDATA%\Axon\AxonSkin\drivers\install-interception.exe | 459KB | 驱动安装程序 |

## 功能推测

基于以下证据:
1. **输入拦截**: interception.dll + install-interception.exe + interception.pending
   - 使用 Interception 驱动 (geoffthecode/interception) 做底层键鼠输入拦截
   - 用于模拟按键/鼠标操作

2. **Qt 6.8.3 GUI**: 大型桌面应用，含多个对话框/标签页

3. **在线验证**: TCP 9486 端口，自定义加密协议，服务端 124.222.192.168

4. **卡密系统**: 32-40 字符卡密，注册表存储，到期时间管理

5. **试用系统**: 一次性试用，注册表标记，机器码绑定 (Dlg_RMBind)

6. **崩溃报告**: 自带崩溃转储 (MiniDumpWriteDump)，写入 %APPDATA%\Axon\AxonSkin\crash\

7. **名称 "AxonSkin"**: 皮肤/外观定制工具，可能涉及:
   - 桌面主题/皮肤系统
   - 窗口外观修改
   - 游戏皮肤相关功能

8. **"Desktop Helper"**: 原始文件名 DeskHelper.exe → 桌面辅助工具

## IDA 分析状态

### 已完成
- ✅ axonlogin.dll 完整反编译 (1079 函数, 796 个 .text 函数反编译为伪代码)
- ✅ axonlogin.dll 导入/导出/字符串提取
- ✅ stub_rr4_mem.bin IDA 加载 (壳 stub 解密代码 16MB)
- ✅ PE 结构完整分析
- ✅ 验证协议抓包解析

### axon_inner.bin 分析 (壳内部 PE)

### 文件信息
- **路径**: `%TEMP%\axon_inner.bin` (565,248 bytes / 552KB)
- **导出**: `SP_Init_v2` (RVA 0x12720)
- **编译器**: MSVC v14 (x64), 静态链接 CRT + WTL + ATL
- **内嵌**: unzip 1.01 (Gilles Vollant)

### RTTI 类名 (揭示全部对话框)
| 类名 | 用途 |
|------|------|
| `Dlg_Login` | 登录对话框 |
| `Dlg_RMBind` | 机器码绑定对话框 |
| `Dlg_OnlineClient` | 在线客户端验证对话框 |
| `Dlg_Main` | **主程序对话框** |
| `CUpdateUI<VDlg_*>` | WTL UI 更新模板 |

### 关键 API
| API | 用途 |
|-----|------|
| `VirtualProtect` | **.text 解密** (修改页保护属性) |
| `VirtualAlloc`/`VirtualFree` | 内存分配 (解密缓冲区) |
| `IsDebuggerPresent` | 反调试检测 |
| `OutputDebugStringW` | 调试输出 |
| `InternetGetConnectedState` | **网络连接检查** (登录前) |
| `RtlLookupFunctionEntry`/`RtlVirtualUnwind` | SEH 异常处理 |
| 注册表 API 全套 | 试用/卡密状态存储 |

### PEB 访问 (4处)
- `0x180013dcd`, `0x180019817`, `0x18002b6b4`, `0x18002b6d0`
- 用于 API 动态解析 (PEB→Ldr→InLoadOrderModuleList)

### 硬编码路径泄露
- `C:\Users\26346\Downloads\AxonSkin v2.3` (开发者本地编译路径)

### IDA 分析
- ✅ 777 个 .text 函数完整反编译 (970KB 伪代码)
- API 通过 `MEMORY[0]` 函数指针数组调用 (运行时填充)

## 明文字符串 (axonlogin.dll .rdata)

**重要发现**: 之前认为 XOR 加密的字符串实际上是**纯 UTF-16LE 中文文本**，ASCII 提取器将中文字节误解为乱码。

### 认证系统 UI 文本
| 地址 | 字符串 |
|------|--------|
| 0x180038B30 | 版本更新 |
| 0x180038B40 | 当前不是最新版本，点击[确定]前往下载最新版本！ |
| 0x180038B56 | [确定]前往下载最新版本！ |
| 0x180038B9E | (请确保操作系统开放了验证端口，以及服务端开启了验证端口。) |
| 0x180038D28 | .lic (许可证文件扩展名) |
| 0x180038DB6 | 错误码:%d |
| 0x180038DF8 | 过期时间:%04d年%02d月%02d日 %02d时%02d分%02d秒 |
| 0x180038E54 | (5s后自动关闭) |
| 0x180038EBA | 但试用卡无法解绑! |
| 0x180038EE4 | 该代理下所有卡密无法登录! |
| 0x180038F48 | IP、机器码不符! |
| 0x180039028 | 错误码:%d |
| 0x180039060 | 本次解绑将消耗赠送的解绑次数(剩余: %d) 是否前往解绑页面? |
| 0x1800390C2 | 已达最多解绑次数, 无法解绑! |
| 0x180039100 | 本次解绑不扣除时长! %s 内剩余解绑次数: %d (含本次) |
| 0x180039578 | 原因可能是: 1.未绑定机器码 2.无绑定机器码属性 3.选中的机器码已被解绑 4.请检查是否已开启[仅允许已绑定机器码进行解绑] |
| 0x1800396A0 | 您已经掉线, 请重新运行程序!! |

### 网络通信 (WinINet HTTP)
| 地址 | 字符串 |
|------|--------|
| 0x180038A70 | https://wwaoo.lanzoue.com/s/daozidan (下载地址/蓝奏云盘) |
| 0x180038AC0 | explorer.exe "%s" |
| 0x180038AE8 | cmd.exe /c start "" "%s" |
| 0x180082940 | InternetOpenW error! |
| 0x180082B38 | InternetOpenUrlW error! |
| 0x180082B80 | InternetReadFile error! |
| 0x180082984 | Accept: */* |
| 0x1800829A0 | Accept-Language: zh-cn |
| 0x1800829D8 | Accept-Encoding: no-gzip, deflate |
| 0x180082A20 | User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/5.1.1.1000 Chrome/55.0... |

### 更新系统
| 地址 | 字符串 |
|------|--------|
| 0x180082BE0 | 可能不是zip文件! |
| 0x180082BFC | zip信息读取失败! |
| 0x1800832D8 | Download progress |
| 0x180083336C | Decompression progress |
| 0x1800833A8 | The update package download is complete .. |
| 0x180083400 | Extracting update package .. |
| 0x180083440 | Update package decompression completed .. |
| 0x180083494 | Starting the main program .. |
| 0x1800834D0 | The upgrade program is about to exit .. |

### 版本信息
| 字段 | 值 |
|------|-----|
| CompanyName | Meridian Software |
| FileDescription | Runtime UI Module |
| ProductName | Meridian Runtime |
| Version | 1.0.0.0 |
| Copyright | Copyright (C) 2026 |

### 动态解析的 API (运行时 GetProcAddress)
- **注册表**: RegOpenKeyExW, RegCreateKeyExW, RegSetValueExW, RegDeleteKeyW, RegQueryValueExW, RegEnumKeyExW, RegCloseKey, RegQueryInfoKeyW
- **注册表事务**: RegOpenKeyTransactedW, RegCreateKeyTransactedW, RegDeleteKeyTransactedW, RegDeleteKeyExW
- **网络**: InternetOpenW, InternetOpenUrlW, InternetReadFile, InternetCloseHandle, InternetGetConnectedState
- **文件**: CreateFileW, WriteFile, ReadFile, DeleteFileW, GetTempFileNameW
- **内存**: VirtualProtect, VirtualAlloc, VirtualFree, HeapAlloc, HeapFree, HeapSize
- **进程**: GetProcessHeap, GetCurrentProcessId, GetModuleHandleW, GetProcAddress, LoadLibraryExW
- **反调试**: IsDebuggerPresent, OutputDebugStringW
- **线程**: CreateThread, CloseHandle, CreateToolhelp32Snapshot
- **COM**: CoInitialize, CoCreateInstance

### 在线认证流程 (sub_1800091D0 @ 0x1800091d0)
```
1. 分配 3 个缓冲区: v3(2049B), v4(101B), v5(129B)
2. 调用 (qword_180050B80 + 144)(&v10, &v8, &v9, v3, v4, v5)
   — 主程序的在线认证回调函数 (虚函数表偏移 +144)
   - 返回值 v6: 1=成功
   - v8: 服务器要求的最低版本号
   - v9, v10: 认证状态
   - v3(2049B): 认证响应数据
   - v4(101B): 卡密/会话信息
   - v5(129B): 机器码信息
3. 重试循环: 3 次, 每次间隔 300ms (Sleep 0x12C)
4. 验证条件: v6==1 AND (v8==0 OR qword_180050B80+128 >= v8)
   — qword_180050B80+128 是程序版本号
   — 如果服务器要求的最低版本 > 当前版本 → 失败
5. 失败 → SetWindowText(错误消息) → Sleep(1200ms) → ExitProcess(0)
```

### 登录对话框资源
| 资源 ID | 标题 | 用途 |
|---------|------|------|
| 0x66 (102) | (主登录对话框) | 登录入口 |
| 0x6A (106) | "在线客户端信息" | Dlg_OnlineClient 在线验证 |
| 0x6B (107) | "已绑定机器码信息" | Dlg_RMBind 机器码绑定 |

## SProtect 虚拟化分析 (unpack7)

### 内存 Dump 结果
- 进程 PID 54824 窗口 "Axon Skin 内测v4.1" — 用户已登录
- 588 个 committed 内存区域，276.8MB + 453.2MB minidump
- **17 个 EXECUTE 代码段**，但 `.text` (38.1MB) 全部为零

### 关键发现：SProtect 代码虚拟化
- `.a1` 段 (30MB) offset 0x1000000+ 有 4664 个函数序言 → **全部是 SProtect VM 混淆代码**
- `.rr4` 段 (130MB) offset 0x07300000+ 有额外 15.5MB 代码 → **同样是 VM 混淆代码**
- 函数特征：`mov [rsp+8], rbx; jmp` 开头 + movabs/xchg/sub/xor/rol/not 混淆链 + ret/hlt/int3
- **所有函数 calls=0** — 无 API 调用，全部通过 VM dispatcher 间接调用
- 真实主程序代码从未被解密为原生 x86-64

### .rr4 导入表 (24MB)
- 58 个依赖 DLL（含 d3d9/d3d11/d3d12, Qt相关, boost, WinHTTP, WS2_32）
- API 名称: CreateFontIndirectW, SHGetKnownFolderPath, D3D11CreateDevice, DWriteCreateFactory 等
- C++ 符号: `__CxxFrameHandler4`, `___lc_codepage_func`, `__std_smf_hypot3f`
- 导入表在 .rr4 offset 0x0，API 调用通过 VM 间接解析

### IDA 分析结果
- 14MB .a1 代码区加载为 raw binary x86-64
- 13805 个函数被自动分析（IDAPython prologue scan）
- 490/500 函数成功反编译，但全部是 VM 混淆代码
- 最大函数 282KB 但只含 4 条有效指令（大量跳转+混淆）

### 功能还原策略修正
由于 SProtect 代码虚拟化，无法直接从内存 dump 还原原始代码。功能还原基于：
1. **axonlogin.dll** (完整明文 PE) — 登录/认证/试用/注册表全部逻辑 ✓
2. **认证协议** (pcapng 分析) — 请求/响应结构 ✓
3. **UI 字符串** (axonlogin.dll .rdata) — 全部认证系统文本 ✓
4. **RTTI 类名** (axon_inner.bin) — Dlg_Main/Dlg_Login/Dlg_RMBind/Dlg_OnlineClient ✓
5. **导入表** (.rr4) — 58 个依赖 DLL 和 API 名称 ✓
6. **运行时行为** (窗口标题 "Axon Skin 内测v4.1") — 确认主程序功能 ✓
7. **应用程序数据** (Axon\AxonSkin\ 目录) — 配置/缓存/驱动/崩溃日志 ✓

## 待完成 (需要运行时 dump)
- ⬜ 主程序 .text (38MB) 解密后代码 — 需在程序运行时 dump
  - 试用已用完，无卡密可用
  - 原版提权进程 pid 44396 已退出
  - asInvoker 副本 pid 52032 已成僵尸
  - **下一步**: 需用户重新启动程序 + 配合 dump
- ⬜ cloud-cfg.bin 解密 (需 DLL 中的解密函数)
- ⬜ Dlg_Main 主程序 UI 逻辑深度分析

## 绕过方案

### 登录绕过
1. **试用重置**: 清除注册表中的试用标记 (需定位注册表键路径)
2. **网络劫持**: 修改 hosts 将 124.222.192.168 指向本地，构造验证响应
3. **DLL Hook**: Hook axonlogin.dll 的 DialogBoxParamW 返回 1 (验证成功)
4. **内存 Patch**: 在壳解密 .text 后, patch 验证检查点

### 反调试绕过
1. 启动前运行 rename_windows.py 重命名窗口标题
2. 使用 asInvoker 副本避免提权检测

## 文件清单
```
axonskin_re/
├── recon/
│   ├── pe_triage.txt           # PE 结构报告
│   └── extract.txt            # 版本信息/壳签名
├── unpack/
│   ├── AxonSkin_v4.1_asInvoker.exe   # manifest patch 副本
│   ├── manifest.json          # 第一个内存 dump 元数据
│   ├── stub_rr4_mem.bin        # 壳 stub 解密代码 (16MB, IDA 可分析)
│   ├── stub_cmp_hashes.txt    # 壳 API hash 常量
│   └── stub_calls.txt         # 壳调用列表
├── plaintext/
│   ├── axonlogin.dll          # 登录 DLL (明文, 已反编译)
│   ├── axon_inner.bin         # 内部 PE (明文)
│   └── axon_bin_res.bin       # 资源 PE (明文)
├── ida_out/
│   ├── functions.txt          # 1079 个函数列表
│   ├── strings.txt            # 字符串列表
│   ├── imports.txt            # 导入表
│   ├── pseudocode_top.txt     # 90 个命名函数伪代码
│   ├── pseudocode_key.txt     # 796 个 .text 函数完整伪代码 (1.08MB)
│   ├── ep_pseudocode.txt      # EP 伪代码
│   └── segments.txt           # 节信息
└── scripts/
    ├── pe_triage.ps1          # PE 分析脚本
    ├── patch_manifest2.py     # manifest 修补
    ├── dump_mem.py            # 内存 dump
    ├── rename_windows.py      # 反调试绕过 (窗口重命名)
    ├── dump_robust.py         # 稳健 dump
    ├── rebuild_pe2.py         # PE 重建
    ├── rebuild_from_regions.py # 从 axon_regions 重建
    ├── find_text_in_regions.py # 查找解密代码区域
    ├── parse_pcapng2.py       # 网络抓包解析
    ├── analyze_cloudcfg.py   # 配置分析
    ├── ida_export.py         # IDA 导出脚本
    ├── ida_decompile_key.py   # IDA 批量反编译
    └── ... (分析脚本)
```
