"""Deep analysis of AxonSkin's actual functionality.
Based on: imports, strings, AppData, RTTI, dialog resources.
Goal: determine what the program actually DOES beyond login."""
import sys, os, re, json, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WORK = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re"

# 1. Analyze crash dumps for clues
print("=== Crash Dumps ===")
crash_dir = os.path.join(os.environ.get('APPDATA', ''), "Axon", "AxonSkin", "crash")
if os.path.exists(crash_dir):
    for f in os.listdir(crash_dir):
        fpath = os.path.join(crash_dir, f)
        size = os.path.getsize(fpath)
        print(f"  {f}: {size/1024:.1f}KB")
        if size > 1000:
            with open(fpath, 'rb') as fp:
                head = fp.read(256)
                # Check for MZ or text
                if head[:4] == b'MDMP':
                    print("    -> Minidump format")
                elif head[:2] == b'MZ':
                    print("    -> PE format")
                else:
                    print(f"    -> First 64 bytes: {head[:64].hex()}")
                    # Try to decode as text
                    try:
                        text = head.decode('utf-8', errors='replace')
                        print(f"    -> Text: {text[:200]}")
                    except:
                        pass

# 2. Analyze AppData files
print("\n=== AppData Analysis ===")
appdata_dir = os.path.join(os.environ.get('APPDATA', ''), "Axon", "AxonSkin")
for root, dirs, files in os.walk(appdata_dir):
    for f in files:
        fpath = os.path.join(root, f)
        relpath = os.path.relpath(fpath, appdata_dir)
        size = os.path.getsize(fpath)
        print(f"\n  {relpath} ({size} bytes)")
        if size < 10000 and size > 0:
            with open(fpath, 'rb') as fp:
                data = fp.read()
            if all(32 <= b <= 126 or b in (10, 13) for b in data[:100]):
                print(f"    Text: {data[:500].decode('ascii', errors='replace')}")
            else:
                print(f"    Hex (first 64): {data[:64].hex()}")
                # Try JSON
                try:
                    j = json.loads(data)
                    print(f"    JSON: {json.dumps(j, indent=2)[:500]}")
                except:
                    pass

# 3. Analyze .rr4 imports for D3D/game-related APIs
print("\n=== D3D/Graphics APIs ===")
imports_path = os.path.join(WORK, "unpack7", "rr4_imports.bin")
with open(imports_path, 'rb') as f:
    imports = f.read()

# Find all API names
api_names = set()
for m in re.finditer(rb'\x00([A-Za-z][a-zA-Z0-9_]{4,50})\x00', imports):
    name = m.group(1).decode('ascii')
    if name[0].isupper() or name.startswith('_'):
        api_names.add(name)

# Categorize
categories = {
    'D3D/Graphics': [],
    'Input/Hook': [],
    'Network': [],
    'Registry/File': [],
    'Process/Thread': [],
    'Memory': [],
    'Window/UI': [],
    'Debug/Anti': [],
    'Other': []
}

for api in sorted(api_names):
    lower = api.lower()
    if any(k in lower for k in ['d3d', 'dxgi', 'gdi', 'direct', 'write', 'dwm', 'theme', 'font']):
        categories['D3D/Graphics'].append(api)
    elif any(k in lower for k in ['hook', 'imm', 'input', 'mouse', 'keyboard', 'cursor']):
        categories['Input/Hook'].append(api)
    elif any(k in lower for k in ['internet', 'http', 'socket', 'ws2', 'dns', 'url', 'wininet']):
        categories['Network'].append(api)
    elif any(k in lower for k in ['reg', 'file', 'path', 'folder', 'create', 'write', 'read']):
        categories['Registry/File'].append(api)
    elif any(k in lower for k in ['process', 'thread', 'module', 'library', 'load', 'toolhelp']):
        categories['Process/Thread'].append(api)
    elif any(k in lower for k in ['virtual', 'heap', 'protect', 'alloc', 'free']):
        categories['Memory'].append(api)
    elif any(k in lower for k in ['window', 'dialog', 'menu', 'message', 'user', 'class']):
        categories['Window/UI'].append(api)
    elif any(k in lower for k in ['debug', 'peb', 'ntquery', 'ntread', 'outputdebug']):
        categories['Debug/Anti'].append(api)
    else:
        categories['Other'].append(api)

for cat, apis in categories.items():
    if apis:
        print(f"\n{cat} ({len(apis)}):")
        for a in apis:
            print(f"  {a}")

# 4. Check for Qt-specific patterns
print("\n=== Qt/D3D Analysis ===")
# Look for Qt class names in imports
qt_patterns = re.findall(rb'(Q\w{4,30})', imports)
qt_classes = set(p.decode('ascii', 'replace') for p in qt_patterns if all(c.isalnum() or c == '_' for c in p.decode('ascii','replace')))
print(f"Qt-related strings: {len(qt_classes)}")
for s in sorted(qt_classes)[:30]:
    print(f"  {s}")
