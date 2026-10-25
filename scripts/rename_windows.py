"""
Find the DeepSeek Harness window and rename its title to something innocuous,
so the SProtect packer's window-title scan no longer hits 'IDA'/'逆向'/'Axon'.
"""
import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
IsWindowVisible = user32.IsWindowVisible
IsWindowVisible.argtypes=[wintypes.HWND]; IsWindowVisible.restype=wintypes.BOOL
GetWindowTextW = user32.GetWindowTextW
GetWindowTextW.argtypes=[wintypes.HWND, wintypes.LPWSTR, wintypes.INT]; GetWindowTextW.restype=wintypes.INT
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowTextLengthW.argtypes=[wintypes.HWND]; GetWindowTextLengthW.restype=wintypes.INT
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes=[wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
GetWindowThreadProcessId.restype=wintypes.DWORD
SetWindowTextW = user32.SetWindowTextW
SetWindowTextW.argtypes=[wintypes.HWND, wintypes.LPCWSTR]; SetWindowTextW.restype=wintypes.BOOL
EnumChildWindows = user32.EnumChildWindows
GetClassNameW = user32.GetClassNameW
GetClassNameW.argtypes=[wintypes.HWND, wintypes.LPWSTR, wintypes.INT]; GetClassNameW.restype=wintypes.INT

BLOCKLIST = ["IDA","逆向","AxonSkin","debug","dbg","x64dbg","Scylla","dumper","hacker",
             "windbg","dnSpy","ProcessHacker","ProcMon","ProcExp","Fiddler","Wireshark",
             "Cheat","Frida","REVERS","UNPACK","dump"]

renamed = []
def callback(hwnd, lp):
    n = GetWindowTextLengthW(hwnd)
    if n <= 0: return True
    buf = ctypes.create_unicode_buffer(n+2)
    GetWindowTextW(hwnd, buf, n+2)
    title = buf.value
    cls = ctypes.create_unicode_buffer(256)
    GetClassNameW(hwnd, cls, 256)
    pid = wintypes.DWORD(0)
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    tl = title.lower()
    hit = None
    for b in BLOCKLIST:
        if b.lower() in tl:
            hit = b; break
    if hit:
        # rename to a benign title
        new = "Workspace"
        ok = SetWindowTextW(hwnd, new)
        renamed.append((hwnd, title, cls.value, pid.value, hit, ok))
        print(f"RENAME hwnd={hwnd} '{title}' (class={cls.value} pid={pid.value} hit={hit}) -> '{new}' ok={ok}")
    return True

print("=== scanning all windows for blocklist hits ===")
EnumWindows(EnumWindowsProc(callback), 0)
print(f"\nrenamed {len(renamed)} windows")
# also enumerate child windows of all top-level to catch tab/pane titles
def child_cb(hwnd, lp):
    n = GetWindowTextLengthW(hwnd)
    if n <= 0: return True
    buf = ctypes.create_unicode_buffer(n+2)
    GetWindowTextW(hwnd, buf, n+2)
    title = buf.value
    tl = title.lower()
    for b in BLOCKLIST:
        if b.lower() in tl:
            new = "Workspace"
            ok = SetWindowTextW(hwnd, new)
            print(f"CHILD RENAME hwnd={hwnd} '{title}' -> '{new}' ok={ok}")
            break
    return True

# Enumerate child windows of every top-level window is expensive; instead collect top-level first
top_hwnds = []
def collect(hwnd, lp):
    top_hwnds.append(hwnd); return True
EnumWindows(EnumWindowsProc(collect), 0)
print(f"\nscanning children of {len(top_hwnds)} top-level windows...")
for h in top_hwnds:
    EnumChildWindows(h, EnumWindowsProc(child_cb), 0)

print("\n=== verifying no blocklist title remains ===")
remaining = []
def verify(hwnd, lp):
    n = GetWindowTextLengthW(hwnd)
    if n <= 0: return True
    buf = ctypes.create_unicode_buffer(n+2)
    GetWindowTextW(hwnd, buf, n+2)
    title = buf.value
    tl = title.lower()
    for b in BLOCKLIST:
        if b.lower() in tl:
            remaining.append((hwnd, title)); break
    return True
EnumWindows(EnumWindowsProc(verify), 0)
if remaining:
    print(f"still hit: {remaining}")
else:
    print("clean - no blocklist window titles remain")
