"""Extract clean API names from .rr4 import table.
The import table has structured format: each DLL has a list of API names.
Look for patterns of consecutive null-terminated ASCII strings."""
import sys, os, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WORK = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\unpack7"

# Read the import table
with open(os.path.join(WORK, "rr4_imports.bin"), "rb") as f:
    data = f.read()

print(f"Import table size: {len(data)/1048576:.1f}MB")

# Find all null-terminated strings that look like API names
# API names: start with uppercase letter, contain only alphanumerics and underscore, 4-60 chars
api_pattern = re.compile(rb'[\x00]([A-Z][a-zA-Z0-9_]{3,60})[\x00]')
matches = api_pattern.findall(data)
print(f"Potential API names: {len(matches)}")

# Also find DLL names followed by API lists
# Pattern: "DLLNAME.dll\x00" followed by API names
dll_apis = {}
current_dll = None
i = 0
while i < len(data) - 4:
    # Check for DLL name
    if data[i:i+1] != b'\x00':
        # Try to read a null-terminated string
        end = data.find(b'\x00', i)
        if end > i and end - i < 200:
            s = data[i:end]
            if s.endswith(b'.dll') or s.endswith(b'.DLL'):
                current_dll = s.decode('ascii', 'replace')
                dll_apis.setdefault(current_dll, [])
                i = end + 1
                continue
            elif current_dll and re.match(rb'^[A-Z][a-zA-Z0-9_]{3,60}$', s):
                api = s.decode('ascii')
                dll_apis[current_dll].append(api)
                i = end + 1
                continue
    i += 1

print(f"\nDLLs with APIs: {len(dll_apis)}")
for dll, apis in sorted(dll_apis.items()):
    if apis:
        print(f"\n{dll} ({len(apis)} APIs):")
        for api in apis[:30]:
            print(f"  {api}")
        if len(apis) > 30:
            print(f"  ... and {len(apis)-30} more")

# Also look for demangled C++ symbols
# Pattern: ?xxx@@... or __xxx
cpp_symbols = set()
for m in re.finditer(rb'\?([A-Za-z_][\w~]{5,200}@@)', data):
    cpp_symbols.add(m.group(0).decode('ascii', 'replace'))
for m in re.finditer(rb'__([a-z_][a-z0-9_]{4,60})', data):
    cpp_symbols.add(m.group(0).decode('ascii', 'replace'))

print(f"\n=== C++ symbols ({len(cpp_symbols)}) ===")
for s in sorted(cpp_symbols)[:50]:
    print(f"  {s[:150]}")

# Save the full list
with open(os.path.join(WORK, "api_list.txt"), "w", encoding="utf-8") as f:
    for dll, apis in sorted(dll_apis.items()):
        if apis:
            f.write(f"=== {dll} ===\n")
            for api in apis:
                f.write(f"  {api}\n")
            f.write("\n")
    f.write(f"\n=== C++ Symbols ===\n")
    for s in sorted(cpp_symbols):
        f.write(f"  {s}\n")

print(f"\nSaved API list to api_list.txt")
