# -*- coding: utf-8 -*-
"""从 village.exe 中按 RVA dump 原始字节并反汇编，核对 Hook C/D 覆盖段的原始编码。"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PE_PATH = r"E:\BaiduNetdiskDownload\Village in the Shade\village.exe"

with open(PE_PATH, "rb") as f:
    data = f.read()

# 解析 PE 头
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

for (rva_start, rva_end, label) in [
    (0x216C90, 0x216CC0, "Hook C 段（含续竿点）"),
    (0x216B40, 0x216B90, "Hook D 段（含入包点）"),
]:
    off = rva_to_off(rva_start)
    length = rva_end - rva_start
    blob = data[off:off+length]
    print(f"\n==== {label}  0x{rva_start:X}-0x{rva_end:X} ====")
    print("原始字节:", blob.hex(" "))
    for insn in md.disasm(blob, rva_start):
        print(f"  0x{insn.address:08X}: {insn.mnemonic}\t{insn.op_str}")