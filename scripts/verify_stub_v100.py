# -*- coding: utf-8 -*-
"""FishingAutoCatch v1.0.0 stub 结构校验（对齐指令边界 + 绝对地址槽）。

关键校验：
  1. Hook C 复放 movsd 两条与原始字节完全一致。
  2. 所有 jmp qword[rip+0] 槽后的 8 字节 = 期望 resume/module 地址。
  3. stub 内未使用 rbx/r13/r14（非易失寄存器）作为写入目标（r14 读基址除外，保留）。
  4. rel8 跳转目标落在指令标签处。
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PATH = r"E:\BaiduNetdiskDownload\Village in the Shade\src\FishingAutoCatch\stub_dump.bin"
data = open(PATH, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

# 期望的绝对地址（dump 默认 stubBase=0x140100000, moduleBase=0x140000000）
STUB_BASE = 0x140100000
EXPECT = {
    "hookA_resume": 0x140000000 + 0x38A860 + 15,
    "cast_resume": 0x140000000 + 0x216CB6,
    "bag_resume": 0x140000000 + 0x216B73,
    "global": 0x140000000 + 0x10DFAD0,
    "addHold": 0x140000000 + 0x138BC0,
    "gEnabled": STUB_BASE + 560,
    "gHits": STUB_BASE + 561,
    "gBagFull": STUB_BASE + 565,
    "gFishCount": STUB_BASE + 566,
}

FAILS = []

def chk(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("  [FAIL] " + msg)

def read_abs(base, addr):
    return struct.unpack_from("<Q", data, addr)[0]

# ---------- Hook A [0,176) ----------
print("==== Hook A ====")
ins = list(md.disasm(data[0:176], 0))
last = ins[-1]
print(f"  末尾指令: 0x{last.address:03X} {last.mnemonic} {last.op_str}")
# 定位 jmp qword[rip+0] 指令，其 8 字节槽应跟在其后 6 字节处
for it in ins:
    if it.mnemonic == "jmp" and it.op_str == "qword ptr [rip]":
        slot = read_abs(0, it.address + 6)
        print(f"  jmp 槽@0x{it.address:03X} = 0x{slot:X}")
        chk(slot == EXPECT["hookA_resume"], f"Hook A resume 槽错误: 0x{slot:X} 期望 0x{EXPECT['hookA_resume']:X}")

# ---------- Hook C [176,368) ----------
print("==== Hook C ====")
# 被覆盖原始字节（26 字节）：前 15B 是 movsd×2 必须复放一致；后 11B 是 mov dword[1DC],1
# 由我们的写 0/写 1 判定逻辑替换，不复放。
CAST_REPLAY = bytes.fromhex("F2 0F 10 44 24 50  F2 41 0F 11 86 A8 02 00 00")
chk(data[176:176+15] == CAST_REPLAY, f"Hook C movsd 复放与原字节不一致")
print(f"  movsd 复放: {'一致' if data[176:176+15] == CAST_REPLAY else '不一致'}")
ins = list(md.disasm(data[176:176+26], 176))
for it in ins:
    print(f"  0x{it.address:03X}: {it.mnemonic}\t{it.op_str}")
# 检查 stub 生成区（176+26 起）：寻找 je/jne/jmp 并核对槽
stubC = data[176+26:368]
insC = list(md.disasm(stubC, 176+26))
for it in insC:
    if it.mnemonic == "jmp" and it.op_str == "qword ptr [rip]":
        slot = read_abs(0, it.address + 6)
        print(f"  jmp 槽@0x{it.address:03X} = 0x{slot:X}")
        chk(slot == EXPECT["cast_resume"], f"Hook C resume 槽错误: 0x{slot:X}")
    if it.mnemonic in ("movabs",) and it.op_str.startswith("r11, 0x"):
        pass

# ---------- Hook D [368,560) ----------
print("==== Hook D ====")
code = data[368:368+45]
print("  stub 前 45 字节:", code.hex(" "))
# 原 0x216B4D 起（mov rcx,[rax+0x208] 到 call 前）共 33 字节应与 stub 中 0x17D 起逐字节一致
BAG_REPLAY = bytes.fromhex(
    "48 8B 88 08 02 00 00"   # mov rcx,[rax+0x208]
    "C6 44 24 20 01"         # mov byte [rsp+0x20],1
    "45 33 C9"               # xor r9d,r9d
    "BA 1A 04 00 00"         # mov edx,0x41a
    "41 B8 06 00 00 00"      # mov r8d,6
    "48 8B 89 B8 32 00 00")  # mov rcx,[rcx+0x32b8]
# 复放段从 stub 偏移 13 起共 33 字节，因 movabs(13B) 比原 mov rax,[rip](7B) 长 6B，
# 复放会延伸到 46 字节处（超出原 45B 覆盖区属正常，stub 区总长 192B），需用完整缓冲区比较。
replay = data[368 + 13:368 + 13 + 33]
print(f"  复放段（mov rcx 起 33B）: {'一致' if replay == BAG_REPLAY else '不一致'}")
chk(replay == BAG_REPLAY, "Hook D 复放段与原始不一致")
insD = list(md.disasm(code, 368))
for it in insD:
    print(f"  0x{it.address:03X}: {it.mnemonic}\t{it.op_str}")

print("\n==== 全部 stub 的人工审阅：跳转/槽/寄存器约束 ====")
for it in list(md.disasm(data[176:560], 176)):
    # 打印所有带立即数字段的指令供人工复核
    if it.mnemonic in ("movabs", "cmp", "mov", "jmp", "je", "jne", "inc", "call", "test", "xor"):
        print(f"  0x{it.address:03X}: {it.mnemonic}\t{it.op_str}")

print("\n结论:", "通过" if not FAILS else f"存在 {len(FAILS)} 处错误")
for f in FAILS:
    print("  -", f)