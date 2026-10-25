"""Analyze .a1 code with capstone to find real functions (not SProtect stubs).
Focus on:
1. Functions >50 bytes (likely real code)
2. Functions with call/jmp to external targets (likely API calls)
3. Functions with string references
"""
import sys, os, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

WORK = r"C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re"

# Read the code
code_path = os.path.join(WORK, "unpack7", "a1_code_live.bin")
with open(code_path, "rb") as f:
    code = f.read()

print(f"Code size: {len(code)/1048576:.1f}MB")

# Read the import table to find API addresses
imports_path = os.path.join(WORK, "unpack7", "rr4_imports.bin")
with open(imports_path, "rb") as f:
    imports_data = f.read()

# Find API names and their approximate offsets
api_names = {}
for m in re.finditer(rb'\x00([A-Z][a-zA-Z0-9_]{4,60})\x00', imports_data):
    name = m.group(1).decode('ascii')
    api_names[m.start()] = name

print(f"Found {len(api_names)} API name entries in import table")

# Use capstone to disassemble
md = Cs(CS_ARCH_X86, CS_MODE_64)

# Find function prologues and analyze each
prologue = b'\x48\x89\x5c\x24'
func_starts = []
pos = 0
while pos < len(code) - 4:
    if code[pos:pos+4] == prologue:
        func_starts.append(pos)
        pos += 1
    else:
        pos += 1

print(f"Function prologues: {len(func_starts)}")

# Analyze larger functions - those that span more bytes before next prologue
real_funcs = []
for i, start in enumerate(func_starts):
    end = func_starts[i+1] if i+1 < len(func_starts) else len(code)
    size = end - start
    if size > 50:  # >50 bytes = likely real function
        real_funcs.append((start, size))

print(f"Functions >50 bytes: {len(real_funcs)}")

# Disassemble top 100 largest functions
real_funcs.sort(key=lambda x: x[1], reverse=True)
print(f"\nTop 50 functions by size:")
for start, size in real_funcs[:50]:
    # Disassemble
    func_code = code[start:start+size]
    instructions = list(md.disasm(func_code, start))
    
    # Count calls, memory accesses
    calls = sum(1 for ins in instructions if ins.mnemonic == 'call')
    rets = sum(1 for ins in instructions if ins.mnemonic in ('ret', 'retn'))
    jmps = sum(1 for ins in instructions if ins.mnemonic == 'jmp')
    xor_count = sum(1 for ins in instructions if ins.mnemonic == 'xor')
    
    # Check if it looks like obfuscation (many xor/nop/test)
    is_obfus = xor_count > len(instructions) * 0.2
    
    # Get first few instructions
    first_ins = instructions[0] if instructions else None
    first_str = f"{first_ins.mnemonic} {first_ins.op_str}" if first_ins else "N/A"
    
    print(f"  0x{start:08x} size={size:4d} insns={len(instructions):3d} calls={calls} rets={rets} jmps={jmps} xor={xor_count} {'OBFUS' if is_obfus else 'REAL'} first={first_str}")

# Now fully disassemble the top 20 real functions and look for patterns
print(f"\n=== Detailed analysis of top 20 functions ===")
for start, size in real_funcs[:20]:
    func_code = code[start:start+size]
    instructions = list(md.disasm(func_code, start))
    
    # Skip obfuscation stubs
    xor_count = sum(1 for ins in instructions if ins.mnemonic == 'xor')
    if xor_count > len(instructions) * 0.15:
        continue
    
    print(f"\n--- Function at 0x{start:08x} (size={size}, {len(instructions)} instructions) ---")
    for j, ins in enumerate(instructions[:30]):  # First 30 instructions
        raw = ' '.join(f'{b:02x}' for b in func_code[ins.address-start:ins.address-start+ins.size])
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str:40s}  ; {raw}")
    if len(instructions) > 30:
        print(f"  ... ({len(instructions)-30} more)")
