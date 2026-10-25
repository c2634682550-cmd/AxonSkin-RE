// ============================================================================
// AxonSkin v4.1 - 版本更新系统
// 基于: axonlogin.dll .rdata 字符串 + WinHTTP 导入
// 下载: https://wwaoo.lanzoue.com/s/daozidan (蓝奏云盘)
// ============================================================================

#pragma once
#include "common.h"
#include <winhttp.h>
#include <shlwapi.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shlwapi.lib")

class UpdateSystem {
public:
    struct UpdateInfo {
        bool available = false;
        std::wstring latestVersion;
        std::wstring downloadUrl;
        std::wstring releaseNotes;
    };

private:
    static constexpr const wchar_t* DOWNLOAD_URL = L"https://wwaoo.lanzoue.com/s/daozidan";
    static constexpr const wchar_t* USER_AGENT = 
        L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36";
    
    UpdateInfo m_info;
    
public:
    // 检查是否有新版本
    bool CheckForUpdates() {
        // 连接服务器检查版本
        HINTERNET hSession = WinHttpOpen(
            USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return false;
        
        HINTERNET hConnect = WinHttpConnect(
            hSession, L"wwaoo.lanzoue.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"GET", L"/s/daozidan",
            nullptr, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        
        // 添加请求头
        const wchar_t* headers = 
            L"Accept: */*\r\n"
            L"Accept-Language: zh-cn\r\n"
            L"Accept-Encoding: no-gzip, deflate\r\n";
        
        WinHttpAddRequestHeaders(hRequest, headers, (DWORD)-1, 
                                  WINHTTP_ADDREQ_FLAG_ADD);
        
        BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (result) result = WinHttpReceiveResponse(hRequest, nullptr);
        
        if (result) {
            // 读取页面内容, 解析最新版本号
            std::wstring pageContent;
            DWORD bytesRead = 0;
            wchar_t buffer[4096];
            
            do {
                bytesRead = 0;
                if (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                    pageContent.append(buffer, bytesRead / sizeof(wchar_t));
                }
            } while (bytesRead > 0);
            
            // 解析版本号 (蓝奏云页面标题中包含版本)
            // "当前不是最新版本，点击[确定]前往下载最新版本！"
            ParseVersionFromPage(pageContent);
        }
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return m_info.available;
    }
    
    // 提示用户更新
    void PromptUpdate() {
        if (!m_info.available) return;
        
        // "当前不是最新版本，点击[确定]前往下载最新版本！"
        if (MessageBoxW(nullptr,
            L"当前不是最新版本，点击[确定]前往下载最新版本！",
            L"版本更新",
            MB_OKCANCEL | MB_ICONINFORMATION) == IDOK) {
            // 打开下载页面
            ShellExecuteW(nullptr, L"open", DOWNLOAD_URL, nullptr, nullptr, SW_SHOW);
        }
    }
    
    // 下载并安装更新 (带进度显示)
    bool DownloadAndInstall() {
        // "Download progress" / "Decompression progress"
        // "The update package download is complete .."
        // "Extracting update package .."
        // "Update package decompression completed .."
        // "Starting the main program .."
        // "The upgrade program is about to exit .."
        
        // 1. 下载更新包 (ZIP/7z)
        std::wstring tempPath = g_app.appDataPath + L"update\\";
        CreateDirectoryW(tempPath.c_str(), nullptr);
        
        std::wstring updatePkg = tempPath + L"AxonSkin_update.7z";
        
        if (!DownloadFile(m_info.downloadUrl, updatePkg)) {
            return false;
        }
        
        // 2. 解压更新包
        // "Extracting update package .."
        std::wstring extractDir = tempPath + L"extracted\\";
        CreateDirectoryW(extractDir.c_str(), nullptr);
        
        if (!ExtractArchive(updatePkg, extractDir)) {
            return false;
        }
        
        // 3. 替换主程序
        // "Starting the main program .."
        std::wstring newExe = extractDir + L"AxonSkin v4.1.exe";
        std::wstring oldExe = g_app.exePath;
        
        // 备份旧文件
        CopyFileW(oldExe.c_str(), (oldExe + L".bak").c_str(), FALSE);
        
        // 替换
        if (!MoveFileExW(newExe.c_str(), oldExe.c_str(), 
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
            return false;
        }
        
        // 4. 重启程序
        // "The upgrade program is about to exit .."
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        CreateProcessW(oldExe.c_str(), nullptr, nullptr, nullptr, FALSE,
                       0, nullptr, nullptr, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        ExitProcess(0);
        return true;
    }
    
    const UpdateInfo& GetUpdateInfo() const { return m_info; }
    
private:
    void ParseVersionFromPage(const std::wstring& page) {
        // 从蓝奏云页面解析版本号
        // 查找 "v4.1" 或 "v4.x" 模式
        size_t pos = page.find(L"v4.");
        if (pos != std::wstring::npos) {
            m_info.latestVersion = page.substr(pos, 5);
            
            // 比较版本 (简化: 如果版本号不同则有更新)
            if (m_info.latestVersion != L"v4.1") {
                m_info.available = true;
            }
        }
    }
    
    bool DownloadFile(const std::wstring& url, const std::wstring& savePath) {
        // 使用 WinHTTP 下载文件
        // "Download progress"
        
        URL_COMPONENTS urlComp = { sizeof(urlComp) };
        wchar_t host[256] = {};
        wchar_t path[1024] = {};
        urlComp.lpszHostName = host;
        urlComp.dwHostNameLength = 255;
        urlComp.lpszUrlPath = path;
        urlComp.dwUrlPathLength = 1023;
        urlComp.dwSchemeLength = 0;
        
        if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
            return false;
        }
        
        HINTERNET hSession = WinHttpOpen(USER_AGENT,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;
        
        HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
        
        BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (result) result = WinHttpReceiveResponse(hRequest, nullptr);
        
        if (result) {
            FILE* f = _wfopen(savePath.c_str(), L"wb");
            if (f) {
                uint8_t buffer[8192];
                DWORD bytesRead;
                do {
                    bytesRead = 0;
                    if (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                        fwrite(buffer, 1, bytesRead, f);
                    }
                } while (bytesRead > 0);
                fclose(f);
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return true;
            }
        }
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    bool ExtractArchive(const std::wstring& archivePath, const std::wstring& destDir) {
        // "Extracting update package .."
        // 使用 7z 解压 (实际可能使用 7za.exe 或 SevenZip library)
        // 简化: 使用 shell 解压
        
        wchar_t cmd[1024];
        swprintf(cmd, L"x \"%s\" -o\"%s\" -y", archivePath.c_str(), destDir.c_str());
        
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USE_SHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        
        std::wstring sevenZip = g_app.appDataPath + L"7za.exe";
        if (CreateProcessW(sevenZip.c_str(), cmd, nullptr, nullptr, FALSE,
                           0, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 60000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
        
        return false;
    }
};
