"""Extract all meaningful strings from the 112MB main code region (reg_060).
Also extract UTF-16LE strings (Chinese UI text).
This reveals all functionality: UI labels, API endpoints, config keys, feature names."""
import os, re, struct

REG = r"C:\Users\26346\AppData\Local\Temp\axon_regions"
path = os.path.join(REG, "reg_060_7ff7bc94c000.bin")
BASE = 0x7ff7bc94c000

print("reading 112MB...")
data = open(path,"rb").read()
print(f"size: {len(data)/1048576:.1f}MB")

# ASCII strings >= 6 chars
print("extracting ASCII strings...")
ascii_strings = set()
for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
    s = m.group().decode("ascii","replace")
    # filter noise
    if len(s) >= 6:
        ascii_strings.add(s)

print(f"ASCII strings: {len(ascii_strings)}")

# UTF-16LE strings >= 4 chars (Chinese and English)
print("extracting UTF-16LE strings...")
utf16_strings = set()
# scan for pairs where second byte is 0x00 (ASCII UTF-16) or 0x4e-0x9f (CJK)
i = 0
while i < len(data)-3:
    # look for UTF-16LE patterns: a sequence of 2-byte chars where high byte is 0x00 (ASCII) or 0x4e-0x9f (CJK)
    if data[i+1] == 0x00 and 0x20 <= data[i] <= 0x7e:
        # extract run
        start = i
        s = bytearray()
        while i < len(data)-1 and data[i+1] == 0x00 and (0x20 <= data[i] <= 0x7e):
            s.append(data[i]); i += 2
        if len(s) >= 4:
            utf16_strings.add(s.decode("ascii","replace"))
        i += 2
    elif data[i+1] in range(0x4e, 0xa0) and data[i] > 0:
        # CJK
        start = i
        s = bytearray()
        while i < len(data)-1 and ((data[i+1] in range(0x4e,0xa0) and data[i] > 0) or (data[i+1]==0x00 and 0x20<=data[i]<=0x7e)):
            s.append(data[i]); s.append(data[i+1]); i += 2
        if len(s) >= 4:
            try:
                decoded = s.decode("utf-16-le","replace")
                if len(decoded) >= 2:
                    utf16_strings.add(decoded)
            except: pass
        i += 2
    else:
        i += 1

print(f"UTF-16LE strings: {len(utf16_strings)}")

# Categorize and save
OUT = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\ida_out"
with open(os.path.join(OUT,"main_strings_ascii.txt"),"w",encoding="utf-8") as f:
    for s in sorted(ascii_strings):
        f.write(s+"\n")
with open(os.path.join(OUT,"main_strings_utf16.txt"),"w",encoding="utf-8") as f:
    for s in sorted(utf16_strings):
        f.write(s+"\n")

# Print interesting categories
def cat(strings, keywords, label, limit=50):
    hits = [s for s in strings if any(k.lower() in s.lower() for k in keywords)]
    print(f"\n=== {label} ({len(hits)}) ===")
    for s in sorted(hits)[:limit]:
        print(f"  {s}")

all_s = list(ascii_strings) + list(utf16_strings)
cat(all_s, ["http","https","api","url","host","port","socket","connect","download","upload","server"], "NETWORK")
cat(all_s, ["axon","skin","config","setting","profile","preset","theme","style"], "APP_FEATURE")
cat(all_s, ["login","trial","license","key","auth","register","activate","expire","vip","member"], "AUTH")
cat(all_s, ["mouse","keyboard","input","macro","hotkey","inject","intercept","hook","driver","hid","gamepad","controller"], "INPUT")
cat(all_s, [".dll",".exe",".json",".bin",".cfg",".ini",".png",".qss",".qm",".conf"], "FILES")
cat(all_s, ["QMainWindow","QWidget","QDialog","QPushButton","QLabel","QTabWidget","QListWidget","QComboBox","QSlider","QSpinBox","QProgressBar","QMenu","QAction","QToolBar","QStatusBar","QSystemTray"], "QT_UI")
cat(all_s, ["python","lua","script","plugin","module","import"], "SCRIPTING")
cat(all_s, ["mouse_move","mouse_click","key_press","keybd","SetWindowsHook","WH_MOUSE","WH_KEYBOARD","LowLevel"], "HOOKS")
