"""Watch for axonlogin.dll to appear in %TEMP%, then replace it with the patched version.
Also rename windows first to avoid SProtect anti-debug detection."""
import os, sys, time, shutil, ctypes, ctypes.wintypes as w

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PATCHED = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin_patched.dll"
TEMP = os.environ.get('TEMP', r'C:\Users\26346\AppData\Local\Temp')
TARGET = os.path.join(TEMP, "axonlogin.dll")

print(f"[*] Watching for: {TARGET}")
print(f"[*] Patched source: {PATCHED}")
print(f"[*] Patched size: {os.path.getsize(PATCHED)} bytes")

# Wait for the file to appear or change
prev_mtime = 0
attempts = 0
while attempts < 600:  # 10 minutes max
    try:
        if os.path.exists(TARGET):
            cur_mtime = os.path.getmtime(TARGET)
            cur_size = os.path.getsize(TARGET)
            if cur_size == os.path.getsize(PATCHED) and cur_mtime != prev_mtime:
                # File appeared or changed - replace it
                # First try to copy (might fail if locked)
                try:
                    shutil.copy2(PATCHED, TARGET)
                    print(f"[+] Successfully replaced {TARGET} with patched version!")
                    print(f"[+] Patched size: {os.path.getsize(TARGET)} bytes")
                    break
                except PermissionError:
                    # File is locked - try with raw file handle
                    print(f"[!] File locked, trying alternate method...")
                    # Use ctypes to replace
                    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    # MoveFileEx with MOVEFILE_REPLACE_EXISTING
                    # First rename the original
                    backup = TARGET + ".bak"
                    try:
                        os.rename(TARGET, backup)
                        shutil.copy2(PATCHED, TARGET)
                        print(f"[+] Replaced via rename+copy!")
                        break
                    except Exception as e:
                        print(f"[!] Rename failed: {e}")
                        prev_mtime = cur_mtime
            elif cur_size != os.path.getsize(PATCHED):
                # Size mismatch - this is the original unpatched DLL
                # Replace immediately
                try:
                    shutil.copy2(PATCHED, TARGET)
                    print(f"[+] Replaced original (size was {cur_size}, now patched)!")
                    break
                except PermissionError:
                    print(f"[!] Original locked, will retry...")
                    prev_mtime = cur_mtime
    except Exception as e:
        print(f"[!] Error: {e}")
    time.sleep(0.5)
    attempts += 1
else:
    print("[-] Timeout waiting for axonlogin.dll")
