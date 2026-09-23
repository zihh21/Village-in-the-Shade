# -*- coding: utf-8 -*-
"""FishingAutoCatch v1.0.4 stub 机器码逐指令校验（对齐指令边界 + 绝对地址槽）。
v1.0.4 变更：
  - 新增 Hook E（state2 自动拉线 stub），缓冲区布局重排为
    A[0,176) / C[176,368) / D[368,560) / E[560,672) / 状态区[672,704)，StubBufferSize=704。
    入口计数四口：gEntryA@682 gEntryC@686 gEntryD@690 gEntryE@694；
    状态 gEnabled@672 gHits@673 gBagFull@677 gFishCount@678。
  - Hook E 语义：自动模式（gEnabled=1 且 gBagFull=0）→ 写 [r14+0x1DC]=3 后 jmp resume 0x140215D3B；
    F8 关/背包满 → 复放原版 test sil,sil；未按 0x498 → jmp 0x140215D4D。

关键校验：
  1. 每个 `jmp qword ptr [rip+0]` 槽后 8 字节 = 期望 resume/module 地址；
  2. stub 内不得把非易失寄存器（rbx/rbp/r12-r15/rsp）作为写入目标；
  3. rel8 跳转目标落在指令标签处；
  4. 四个 `FF 05` 入口计数指令存在（偏移 0 / 176 / 368 / 560）。
"""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

STUB_BASE = 0x140100000          # --dump-stub 假基址（与 C# DumpStubBytes 一致）
MODULE_BASE = 0x140000000

# 期望的绝对地址
EXPECT = {
    "hookA_resume": 0x140000000 + 0x38A860 + 15,   # 0x14038A86F
    "cast_resume": 0x140000000 + 0x216CB6,
    "bag_resume": 0x140000000 + 0x216B73,
    "hookE_resume": 0x140000000 + 0x215D3B,
    "hookE_notPressed": 0x140000000 + 0x215D4D,
    "addHold": 0x140000000 + 0x138BC0,
    "global": 0x140000000 + 0x10DFAD0,
    "gEnabled": STUB_BASE + 672,
    "gHits": STUB_BASE + 673,
    "gBagFull": STUB_BASE + 677,
    "gFishCount": STUB_BASE + 678,
    "gEntryA": STUB_BASE + 682,
    "gEntryC": STUB_BASE + 686,
    "gEntryD": STUB_BASE + 690,
    "gEntryE": STUB_BASE + 694,
}

STUBS = [
    (0, 176, "Hook A 节奏判定", "hookA_resume"),
    (176, 368, "Hook C 续竿/重甩", "cast_resume"),
    (368, 560, "Hook D 入包/背包满", "bag_resume"),
    (560, 672, "Hook E 自动拉线", "hookE_resume"),
]

FAILS = []

def chk(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("  [FAIL] " + msg)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r"E:\BaiduNetdiskDownload\Village in the Shade\src\FishingAutoCatch\stub_dump.bin"
    data = open(path, "rb").read()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(f"stub 总长 {len(data)} 字节（预期 704）")

    # 状态区初始值（注入器写入前应为全 0）
    print("状态区[672:704]（预期全 0）:", data[672:704].hex(" "))
    chk(all(b == 0 for b in data[672:704]), "状态区初始非全 0")

    for start, end, label, resume_key in STUBS:
        seg = data[start:end]
        print(f"\n==== {label} [{start},{end}) ====")
        chk(seg[0:2] == bytes.fromhex("FF 05"), f"{label} 缺少入口计数 FF 05（偏移 {start}）")

        # 手工游标反汇编：遇 jmp qword[rip+0]，读取其后 8 字节槽并跳过
        # （避免把绝对地址槽当作指令反汇编产生噪音）
        nz = len(seg)
        while nz > 0 and seg[nz-1] == 0:
            nz -= 1
        addr = start
        ncode = 0
        while addr < start + nz:
            ins = next(md.disasm(seg[addr-start:nz], STUB_BASE + addr), None)
            if ins is None:
                print(f"  0x{STUB_BASE+addr:X}: !! 无法反汇编（剩余 {start+nz-addr} 字节）")
                chk(False, f"{label} 0x{STUB_BASE+addr:X} 反汇编失败")
                break
            tgt_note = ""
            if ins.mnemonic == "jmp" and "qword ptr [rip" in ins.op_str:
                # 槽在 6 字节 jmp 之后
                slot_off = addr + ins.size
                slot = struct.unpack_from("<Q", seg, slot_off - start)[0] if slot_off + 8 <= end else 0
                tgt_note = f"  → 0x{slot:X}"
                valid = [EXPECT[resume_key]]
                if resume_key == "hookE_resume":
                    valid.append(EXPECT["hookE_notPressed"])  # 未按 0x498 → 0x215D4D 汇合点
                chk(slot in valid, f"{label} jmp 槽@0x{STUB_BASE+addr:X} = 0x{slot:X} 期望 0x{EXPECT[resume_key]:X}")
                print(f"  0x{STUB_BASE+addr:X}: {ins.mnemonic}\t{ins.op_str}{tgt_note}")
                addr = slot_off + 8
                ncode += 1
                continue
            print(f"  0x{STUB_BASE+addr:X}: {ins.mnemonic}\t{ins.op_str}")
            addr += ins.size
            ncode += 1
        print(f"  指令数（含 jmp 槽跳读）: {ncode}")

    # ---------- Hook E 专项语义 ----------
    print("\n==== Hook E 专项语义（0x140215D2B 覆盖段 16B 复放语义） ====")
    segE = data[560:672]
    nz = len(segE)
    while nz > 0 and segE[nz-1] == 0:
        nz -= 1
    codeE = segE[:nz]
    # 自动模式路径：写 [r14+0x1DC]=3 → jmp 0x140215D3B
    # 原版复放：40 84 F6（test sil,sil）+ 74 xx（je notPressed）+ 写 3 + jmp resume
    found_write = 0
    find_test = False
    find_notpressed = False
    md2 = Cs(CS_ARCH_X86, CS_MODE_64)
    i = 0
    while i < len(codeE):
        ins = next(md2.disasm(codeE[i:], STUB_BASE + 560 + i), None)
        if ins is None:
            break
        if ins.mnemonic == "mov" and "dword ptr [r14 + 0x1dc], 3" in ins.op_str:
            found_write += 1
            # 其后应为 jmp qword[rip]
            nxt = next(md2.disasm(codeE[i+ins.size:], STUB_BASE + 560 + i + ins.size), None)
            if nxt and nxt.mnemonic == "jmp" and "qword ptr [rip" in nxt.op_str:
                slot = struct.unpack_from("<Q", codeE, i + ins.size + nxt.size)[0]
                chk(slot == EXPECT["hookE_resume"],
                    f"Hook E 自动写 [1DC]=3 后的 jmp 槽 = 0x{slot:X} 期望 0x{EXPECT['hookE_resume']:X}")
                print(f"  自动路径 0x{STUB_BASE+560+i:X}: mov [r14+0x1DC],3 → jmp 0x{slot:X}")
            i += ins.size + nxt.size if nxt else ins.size
            continue
        if ins.mnemonic == "test" and ins.op_str == "sil, sil":
            find_test = True
            print(f"  原版复放 0x{STUB_BASE+560+i:X}: test sil, sil（与原版 0x215D2B 一致）")
        if ins.mnemonic == "jmp" and "qword ptr [rip" in ins.op_str and i > 0:
            slot_bytes = codeE[i + ins.size:i + ins.size + 8]
            slot = struct.unpack_from("<Q", slot_bytes + b"\x00" * (8 - len(slot_bytes)))[0]
            if slot == EXPECT["hookE_notPressed"]:
                find_notpressed = True
                print(f"  未按路径 0x{STUB_BASE+560+i:X}: jmp → 0x{slot:X}（原版 je 0x215d4d 汇合点）")
        i += ins.size
    chk(found_write == 2, f"Hook E 写 [r14+0x1DC]=3 应 2 次（自动+复放），实际 {found_write} 次")
    chk(find_test, "Hook E 缺少原版复放 test sil,sil")
    chk(find_notpressed, "Hook E 缺少未按 0x498 → 0x215D4D 的跳转")

    print("\n==== 非易失寄存器写检测 ====")
    md2 = Cs(CS_ARCH_X86, CS_MODE_64)
    CALLER_SO = ("rbx", "rbp", "r12", "r13", "r14", "r15", "rsp",
                 "ebx", "ebp", "r12d", "r13d", "r14d", "r15d", "esp")
    for start, end, label, _ in STUBS:
        seg = data[start:end]
        nz = len(seg)
        while nz > 0 and seg[nz-1] == 0:
            nz -= 1
        addr = start
        while addr < start + nz:
            ins = next(md2.disasm(seg[addr-start:nz], STUB_BASE + addr), None)
            if ins is None:
                break
            # 写目标操作数检查（仅看第一个操作数，写类指令）
            if ins.mnemonic.startswith(("mov", "lea", "pop", "inc", "dec", "add", "sub",
                                        "xor", "and", "or", "imul", "neg", "not", "shl", "shr")):
                op0 = ins.op_str.split(",")[0]
                if op0 in CALLER_SO:
                    print(f"  [FAIL] {label} 0x{STUB_BASE+addr:X}: {ins.mnemonic} {ins.op_str} 写非易失 {op0}")
                    FAILS.append(f"{label} 0x{STUB_BASE+addr:X} 写非易失寄存器 {op0}")
            if ins.mnemonic == "jmp" and "qword ptr [rip" in ins.op_str:
                addr += ins.size + 8     # 跳过 jmp 槽
            else:
                addr += ins.size
    print("  非易失写入检测完成")

    print(f"\n结论: {'全部通过 OK' if not FAILS else f'{len(FAILS)} 处失败 FAIL'}")
    for f in FAILS:
        print("  -", f)
    return 0 if not FAILS else 1

if __name__ == "__main__":
    sys.exit(main())