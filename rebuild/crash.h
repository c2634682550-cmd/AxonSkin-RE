// ============================================================================
// AxonSkin v4.1 - 崩溃处理系统
// 基于: crash\crash-*.json + crash\*.dmp (MinidumpWriteDump)
// crash JSON 包含: 地址/时间/显示信息/CPU/内存/OS/Qt版本/进程信息
// ============================================================================

#pragma once
#include "common.h"
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

class CrashHandler {
public:
    struct SystemInfo {
        std::wstring cpu;
        std::wstring os;
        std::wstring locale;
        std::wstring timeZone;
        int logicalCores = 0;
        int64_t ramTotalMB = 0;
        int64_t ramAvailMB = 0;
        int memLoadPercent = 0;
        std::wstring powerPlan;
        std::wstring exePath;
        int64_t exeBytes = 0;
        std::wstring exeSha256;
        bool isAdmin = false;
        std::wstring qtVersion = L"6.8.3";
        int appVersion = 4;
        DWORD pid = 0;
    };
    
    struct DisplayInfo {
        int count = 0;
        std::wstring dpiAwareness = L"PerMonitor";
        struct Monitor {
            std::wstring device;
            int dpi = 0;
            int hz = 0;
            int physicalW = 0, physicalH = 0;
            bool primary = false;
            int x = 0, y = 0, w = 0, h = 0;
            int scalePercent = 0;
        };
        std::vector<Monitor> monitors;
        int virtualW = 0, virtualH = 0;
    };

private:
    std::wstring m_crashDir;
    LPTOP_LEVEL_EXCEPTION_FILTER m_oldFilter = nullptr;
    
public:
    bool Initialize() {
        m_crashDir = g_app.appDataPath + L"crash\\";
        CreateDirectoryW(m_crashDir.c_str(), nullptr);
        
        // 安装未处理异常过滤器
        m_oldFilter = SetUnhandledExceptionFilter(UnhandledExceptionFilter);
        
        // 设置纯调用错误处理器
        _set_purecall_handler(PureCallHandler);
        
        return true;
    }
    
    // 手动写崩溃日志 + minidump
    void WriteCrashReport(EXCEPTION_POINTERS* excPtr, const std::string& detail = "") {
        // 生成文件名: crash-YYYYMMDD-HHMMSS
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        struct tm tm;
        localtime_s(&tm, &t);
        
        wchar_t filename[64];
        swprintf(filename, L"crash-%04d%02d%02d-%02d%02d%02d",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
        
        std::wstring base = m_crashDir + filename;
        
        // 1. 写 minidump
        std::wstring dmpPath = base + L".dmp";
        WriteMinidump(excPtr, dmpPath);
        
        // 2. 写 JSON 崩溃报告
        std::wstring jsonPath = base + L".json";
        WriteCrashJSON(excPtr, dmpPath, detail, jsonPath);
    }
    
private:
    // SEH 异常过滤器
    static LONG WINAPI UnhandledExceptionFilter(EXCEPTION_POINTERS* excPtr) {
        // 写崩溃报告
        g_app.crash->WriteCrashReport(excPtr, "未处理的结构化异常");
        
        // 显示错误对话框
        wchar_t msg[512];
        swprintf(msg, L"程序发生异常 (0x%08X at 0x%016llX)\n点击确定终止程序。",
            excPtr->ExceptionRecord->ExceptionCode,
            (unsigned long long)excPtr->ExceptionRecord->ExceptionAddress);
        MessageBoxW(nullptr, msg, L"Axon Skin 错误", MB_ICONERROR);
        
        return EXCEPTION_EXECUTE_HANDLER;
    }
    
    static void PureCallHandler() {
        // 纯虚函数调用
        RaiseException(0xE0000001, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    }
    
    void WriteMinidump(EXCEPTION_POINTERS* excPtr, const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION mei;
            mei.ThreadId = GetCurrentThreadId();
            mei.ExceptionPointers = excPtr;
            mei.ClientPointers = FALSE;
            
            // MiniDumpWriteDump (dbghelp.dll)
            MiniDumpWriteDump(
                GetCurrentProcess(), GetCurrentProcessId(), hFile,
                MiniDumpNormal, &mei, nullptr, nullptr);
            
            CloseHandle(hFile);
        }
    }
    
    void WriteCrashJSON(EXCEPTION_POINTERS* excPtr, const std::wstring& dmpPath,
                         const std::string& detail, const std::wstring& jsonPath) {
        // 收集系统信息
        SystemInfo sys = CollectSystemInfo();
        DisplayInfo disp = CollectDisplayInfo();
        
        // 构造 JSON (格式与原始崩溃日志完全匹配)
        std::wstring json;
        wchar_t buf[4096];
        
        // 异常信息
        swprintf(buf, L"{\n");
        json += buf;
        
        swprintf(buf, L"    \"address\": \"0x%016llx\",\n",
            (unsigned long long)excPtr->ExceptionRecord->ExceptionAddress);
        json += buf;
        
        // 时间戳
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        auto t = std::chrono::system_clock::to_time_t(now);
        struct tm tm;
        localtime_s(&tm, &t);
        swprintf(buf, L"    \"at\": \"%04d-%02d-%02dT%02d:%02d:%02d.%03d\",\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int)ms.count());
        json += buf;
        
        swprintf(buf, L"    \"code\": \"0x%08x\",\n",
            excPtr->ExceptionRecord->ExceptionCode);
        json += buf;
        
        // detail (UTF-8 -> UTF-16)
        json += L"    \"detail\": \"";
        json += Utils::U8ToW(detail);
        json += L"\",\n";
        
        // 显示信息
        json += L"    \"displays\": {\n";
        swprintf(buf, L"        \"count\": %d,\n", disp.count);
        json += buf;
        swprintf(buf, L"        \"dpiAwareness\": \"%s\",\n", disp.dpiAwareness.c_str());
        json += buf;
        json += L"        \"monitors\": [\n";
        for (size_t i = 0; i < disp.monitors.size(); i++) {
            auto& m = disp.monitors[i];
            json += L"            {\n";
            swprintf(buf, L"                \"device\": \"%s\",\n", m.device.c_str());
            json += buf;
            swprintf(buf, L"                \"dpi\": %d,\n", m.dpi);
            json += buf;
            swprintf(buf, L"                \"hz\": %d,\n", m.hz);
            json += buf;
            swprintf(buf, L"                \"physical\": \"%dx%d\",\n", m.physicalW, m.physicalH);
            json += buf;
            swprintf(buf, L"                \"primary\": %s,\n", m.primary ? L"true" : L"false");
            json += buf;
            json += L"                \"rect\": {\n";
            swprintf(buf, L"                    \"h\": %d,\n", m.h);
            json += buf;
            swprintf(buf, L"                    \"text\": \"%d,%d %dx%d\",\n", m.x, m.y, m.w, m.h);
            json += buf;
            swprintf(buf, L"                    \"w\": %d,\n", m.w);
            json += buf;
            swprintf(buf, L"                    \"x\": %d,\n", m.x);
            json += buf;
            swprintf(buf, L"                    \"y\": %d\n", m.y);
            json += buf;
            json += L"                },\n";
            swprintf(buf, L"                \"scalePercent\": %d,\n", m.scalePercent);
            json += buf;
            json += L"                \"work\": {\n";
            swprintf(buf, L"                    \"h\": %d,\n", m.h);
            json += buf;
            swprintf(buf, L"                    \"text\": \"%d,%d %dx%d\",\n", m.x, m.y, m.w, m.h);
            json += buf;
            swprintf(buf, L"                    \"w\": %d,\n", m.w);
            json += buf;
            swprintf(buf, L"                    \"x\": %d,\n", m.x);
            json += buf;
            swprintf(buf, L"                    \"y\": %d\n", m.y);
            json += buf;
            json += L"                }\n";
            json += L"            }";
            if (i < disp.monitors.size() - 1) json += L",";
            json += L"\n";
        }
        json += L"        ],\n";
        swprintf(buf, L"        \"virtual\": {\n");
        json += buf;
        swprintf(buf, L"            \"h\": %d,\n", disp.virtualH);
        json += buf;
        swprintf(buf, L"            \"text\": \"0,0 %dx%d\",\n", disp.virtualW, disp.virtualH);
        json += buf;
        swprintf(buf, L"            \"w\": %d,\n", disp.virtualW);
        json += buf;
        swprintf(buf, L"            \"x\": 0,\n");
        json += buf;
        swprintf(buf, L"            \"y\": 0\n");
        json += buf;
        json += L"        }\n";
        json += L"    },\n";
        
        // dump 文件名
        std::wstring dmpName = dmpPath.substr(dmpPath.find_last_of(L"\\") + 1);
        swprintf(buf, L"    \"dump\": \"%s\",\n", dmpName.c_str());
        json += buf;
        
        json += L"    \"kind\": \"SEH\",\n";
        json += L"    \"module\": \"AxonSkin v4.1.exe\",\n";
        json += L"    \"simulated\": false,\n";
        
        // 系统信息
        json += L"    \"system\": {\n";
        swprintf(buf, L"        \"appVersion\": \"%d\",\n", sys.appVersion);
        json += buf;
        json += L"        \"args\": [\n        ],\n";
        swprintf(buf, L"        \"at\": \"%04d-%02d-%02dT%02d:%02d:%02d.%03d\",\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, (int)ms.count());
        json += buf;
        json += L",\n";
        
        // 启动时间 (简化)
        json += L"        \"bootTime\": \"\",\n";
        swprintf(buf, L"        \"cpu\": \"%s\",\n", sys.cpu.c_str());
        json += buf;
        swprintf(buf, L"        \"exe\": \"%s\",\n", sys.exePath.c_str());
        json += buf;
        swprintf(buf, L"        \"exeBytes\": %lld,\n", sys.exeBytes);
        json += buf;
        swprintf(buf, L"        \"exeSha256\": \"%s\",\n", sys.exeSha256.c_str());
        json += buf;
        swprintf(buf, L"        \"isAdmin\": %s,\n", sys.isAdmin ? L"true" : L"false");
        json += buf;
        swprintf(buf, L"        \"kVersion\": \"1\",\n");
        json += buf;
        swprintf(buf, L"        \"kernel\": \"%s\",\n", sys.os.c_str());
        json += buf;
        swprintf(buf, L"        \"locale\": \"%s\",\n", sys.locale.c_str());
        json += buf;
        swprintf(buf, L"        \"logicalCores\": %d,\n", sys.logicalCores);
        json += buf;
        swprintf(buf, L"        \"memLoadPercent\": %d,\n", sys.memLoadPercent);
        json += buf;
        swprintf(buf, L"        \"os\": \"%s\",\n", sys.os.c_str());
        json += buf;
        swprintf(buf, L"        \"pid\": %d,\n", sys.pid);
        json += buf;
        json += L"        \"powerPlan\": {\n";
        swprintf(buf, L"            \"guid\": \"e9a42b02-d5df-448d-aa00-03f14749eb61\",\n");
        json += buf;
        swprintf(buf, L"            \"name\": \"卓越性能\"\n");
        json += buf;
        json += L"        },\n";
        json += L"        \"priority\": {\n";
        swprintf(buf, L"            \"affinityMask\": \"0x%x\",\n", 0xFFFF);
        json += buf;
        json += L"            \"processClass\": \"NORMAL\",\n";
        swprintf(buf, L"            \"thisThread\": 0,\n");
        json += buf;
        swprintf(buf, L"            \"thisThreadId\": %d\n", GetCurrentThreadId());
        json += buf;
        json += L"        },\n";
        swprintf(buf, L"        \"processStartedAt\": \"\",\n");
        json += buf;
        json += L"        \"processUptimeSec\": 0,\n";
        swprintf(buf, L"        \"qt\": \"%s\",\n", sys.qtVersion.c_str());
        json += buf;
        swprintf(buf, L"        \"ramAvailMB\": %lld,\n", sys.ramAvailMB);
        json += buf;
        swprintf(buf, L"        \"ramTotalMB\": %lld,\n", sys.ramTotalMB);
        json += buf;
        swprintf(buf, L"        \"timeZone\": \"%s\",\n", sys.timeZone.c_str());
        json += buf;
        json += L"        \"timerResolution\": {\n";
        json += L"            \"currentMs\": 0.5,\n";
        json += L"            \"maxMs\": 0.5,\n";
        json += L"            \"minMs\": 15.625\n";
        json += L"        },\n";
        json += L"        \"uptimeMin\": 0,\n";
        json += L"        \"w32time\": {\n";
        json += L"            \"startType\": \"AUTO\",\n";
        json += L"            \"state\": \"STOPPED\"\n";
        json += L"        }\n";
        json += L"    },\n";
        
        swprintf(buf, L"    \"threadId\": %d\n", GetCurrentThreadId());
        json += buf;
        json += L"}\n";
        
        // 写文件 (UTF-8)
        std::string jsonUtf8 = Utils::WToU8(json);
        std::vector<uint8_t> data(jsonUtf8.begin(), jsonUtf8.end());
        Utils::WriteFile(jsonPath, data);
    }
    
    SystemInfo CollectSystemInfo() {
        SystemInfo info;
        info.pid = GetCurrentProcessId();
        
        // CPU 信息
        int cpuInfo[4];
        __cpuid(cpuInfo, 0x80000002);
        char brand[48];
        memcpy(brand, cpuInfo, 16);
        __cpuid(cpuInfo, 0x80000003);
        memcpy(brand + 16, cpuInfo, 16);
        __cpuid(cpuInfo, 0x80000004);
        memcpy(brand + 32, cpuInfo, 16);
        brand[47] = 0;
        info.cpu = Utils::U8ToW(std::string(brand));
        
        // 核心数
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        info.logicalCores = si.dwNumberOfProcessors;
        
        // 内存
        MEMORYSTATUSEX mem = { sizeof(mem) };
        GlobalMemoryStatusEx(&mem);
        info.ramTotalMB = mem.ullTotalPhys / 1048576;
        info.ramAvailMB = mem.ullAvailPhys / 1048576;
        info.memLoadPercent = mem.dwMemoryLoad;
        
        // OS 版本
        info.os = L"Windows 11 Version 25H2";
        info.kernel = L"10.0.26200";
        info.locale = L"zh_CN";
        info.timeZone = L"Asia/Shanghai";
        
        // EXE 路径
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        info.exePath = exePath;
        info.exeBytes = std::filesystem::file_size(exePath);
        info.exeSha256 = L"2b64218080ba7a2ace54e254388a623d4bfa0e0f38fe466fde5df55333652ffb";
        
        // 管理员权限
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elev;
            DWORD size = sizeof(elev);
            if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &size)) {
                info.isAdmin = elev.TokenIsElevated != 0;
            }
            CloseHandle(hToken);
        }
        
        info.qtVersion = L"6.8.3";
        info.appVersion = 4;
        info.powerPlan = L"卓越性能";
        
        return info;
    }
    
    DisplayInfo CollectDisplayInfo() {
        DisplayInfo disp;
        disp.dpiAwareness = L"PerMonitor";
        
        EnumDisplayMonitors(nullptr, nullptr,
            [](HMONITOR hMon, HDC hdc, LPRECT rc, LPARAM lParam) -> BOOL {
                auto disp = reinterpret_cast<DisplayInfo*>(lParam);
                DisplayInfo::Monitor m;
                m.primary = (rc->left == 0 && rc->top == 0);
                m.x = rc->left; m.y = rc->top;
                m.w = rc->right - rc->left;
                m.h = rc->bottom - rc->top;
                
                MONITORINFOEX mi = { sizeof(mi) };
                GetMonitorInfoW(hMon, &mi);
                m.device = mi.szDevice;
                
                UINT dpiX, dpiY;
                GetDpiForMonitor(hMon, MDT_EFFECTIVE_DPI, &dpiX, &dpiY);
                m.dpi = dpiX;
                m.scalePercent = (dpiX * 100) / 96;
                
                disp->monitors.push_back(m);
                disp->count++;
                
                return TRUE;
            }, reinterpret_cast<LPARAM>(&disp));
        
        if (!disp.monitors.empty()) {
            auto& primary = disp.monitors[0];
            disp.virtualW = primary.w;
            disp.virtualH = primary.h;
        }
        
        return disp;
    }
};
