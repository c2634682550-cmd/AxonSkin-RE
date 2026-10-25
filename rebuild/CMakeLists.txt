# AxonSkin v4.1 重建 - CMake 构建配置
cmake_minimum_required(VERSION 3.16)
project(AxonSkinRebuild CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 源文件
set(SOURCES main.cpp)

# 头文件
set(HEADERS
    common.h
    auth.h
    config.h
    d3d_hook.h
    input_hook.h
    update.h
    crash.h
    ui.h
)

# 可执行文件 (GUI 程序)
add_executable(AxonSkin WIN32 ${SOURCES} ${HEADERS})

# Windows 库依赖
target_link_libraries(AxonSkin PRIVATE
    ws2_32          # WinSock (认证协议)
    iphlpapi        # IP Helper (机器码)
    winhttp         # HTTP (云端配置/更新)
    d3d9            # Direct3D 9 (皮肤渲染)
    d3d11           # Direct3D 11 (皮肤渲染)
    dxgi            # DXGI (交换链)
    dwrite          # DirectWrite (文字渲染)
    dwmapi          # DWM (窗口合成)
    d2d1            # Direct2D
    gdiplus         # GDI+ (图像)
    setupapi        # 设备安装 (拦截驱动)
    comctl32        # 通用控件
    comdlg32        # 通用对话框
    ole32           # COM
    oleaut32        # OLE Automation
    shell32         # Shell
    shlwapi         # Shell 轻量 API
    shcore          # Shell Core (DPI)
    uxtheme         # 主题
    imm32           # 输入法
    winmm           # 多媒体
    wtsapi32        # 终端服务
    dbghelp         # 崩溃 dump
    version         # 版本信息
    crypt32         # 加密
    ncrypt          # 加密
    bcrypt          # 加密
    secur32         # 安全
    advapi32        # 高级 API (注册表)
    user32          # 用户界面
    gdi32           # GDI
    kernel32        # 内核
    psapi           # 进程信息
    userenv         # 用户环境
    netapi32        # 网络 API
    authz           # 授权
    dnsapi          # DNS
)

# 预处理器定义
target_compile_definitions(AxonSkin PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00  # Windows 10
)

# 控制台子模式 (调试用)
add_executable(AxonSkinConsole ${SOURCES} ${HEADERS})
target_link_libraries(AxonSkinConsole PRIVATE
    ${same_libs_as_above}
)
target_compile_definitions(AxonSkinConsole PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN
    AXONSKIN_CONSOLE_MODE
)
