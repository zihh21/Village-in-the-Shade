# -*- coding: utf-8 -*-
"""从 village.exe 中按 RVA dump Hook E（state2 自动拉线 0x215D2B）覆盖段的原始编码，并扫描跳入点。"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PE_PATH = r"E:\BaiduNetdiskDownload\Village in the Shade\village.exe"

with open(PE_PATH, "rb") as f:
    data = f.read()

assert data[:2] == b"MZ"
pe_off = struct.unpack_from("<I", data, 0x3C)[0]
assert data[pe_off:pe_off+4] == b"PE\x00\x00"
num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
sec_off = pe_off + 24 + opt_size

sections = []
for i in range(num_sections):
    base = sec_off + i * 40
    name = data[base:base+8].rstrip(b"\x00").decode("ascii", "ignore")
    vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, base + 8)
    sections.append((name, vaddr, vsize, roff, rsize))

def rva_to_off(rva):
    for name, vaddr, vsize, roff, rsize in sections:
        if vaddr <= rva < vaddr + vsize:
            return roff + (rva - vaddr)
    raise ValueError(f"RVA 0x{rva:X} 不在任何节内")

md = Cs(CS_ARCH_X86, CS_MODE_64)

# Hook E 候选点：0x215D2B（state2 检测 0x498 后写 [r14+0x1DC]=3）
HOOK_E = 0x215D2B
PATCH_LEN = 16          # 覆盖 test sil,sil(3) + je rel8(2) + mov [r14+0x1DC],3(11) = 16
RESUME = HOOK_E + PATCH_LEN   # 0x215D3B（cmp [r14+0x238],0）

off = rva_to_off(HOOK_E)
blob = data[off:off+PATCH_LEN+32]
print(f"==== Hook E 段 0x{HOOK_E:X}-0x{HOOK_E+PATCH_LEN+32:X} ====")
print("原始字节:", blob.hex(" "))
for insn in md.disasm(blob, HOOK_E):
    print(f"  0x{insn.address:08X}: {insn.mnemonic}\t{insn.op_str}")

# ---- 扫描整个 .text 中所有跳入 0x215D2B..0x215D3B 的指令 ----
print("\n==== 跳入 Hook E 覆盖区间（0x215D2B-0x215D3B）的指令扫描 ====")
md2 = Cs(CS_ARCH_X86, CS_MODE_64)
text_start, text_size = None, None
for name, vaddr, vsize, roff, rsize in sections:
    if name == ".text":
        text_start, text_size = vaddr, vsize
        break
text_off = rva_to_off(text_start)

# .text 一般远大于 16MB，这里按"当前已分析函数切片即可"，全扫耗时大。
# 改为重点扫描 state2 handler 区域 0x215AAE..0x215E28 段内的相对跳转目标。
SCAN_RANGE = (0x215600, 0x216000)
code = data[rva_to_off(SCAN_RANGE[0]):rva_to_off(SCAN_RANGE[1])]
for insn in md2.disasm(code, SCAN_RANGE[0]):
    if insn.mnemonic in ("jmp", "je", "jne", "jb", "jae", "ja", "jbe", "jz", "jnz", "loop", "jecxz") or insn.mnemonic.startswith("j"):
        try:
            tgt = int(insn.op_str, 16)
        except ValueError:
            continue
        if HOOK_E <= tgt < HOOK_E + PATCH_LEN:
            print(f"  0x{insn.address:08X}: {insn.mnemonic}\t{insn.op_str}  ← 跳入覆盖区间!")

# ---- 0x215D2B 自身是哪些跳转的目标 ----
print("\n==== 扫描引用 0x215D2B 的跳转（state2 附近） ====")
for insn in md2.disasm(code, SCAN_RANGE[0]):
    if insn.mnemonic in ("jmp", "je", "jne", "jb", "jae", "ja", "jbe", "jz", "jnz") or insn.mnemonic.startswith("j"):
        try:
            tgt = int(insn.op_str, 16)
        except ValueError:
            continue
        if tgt == HOOK_E:
            print(f"  0x{insn.address:08X}: {insn.mnemonic}\t{insn.op_str}  ← 跳到 Hook E 入口")