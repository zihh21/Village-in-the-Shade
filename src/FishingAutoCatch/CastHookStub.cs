using System;

namespace FishingAutoCatch
{
    /// <summary>
    /// v1.0.0 新增的两个 Hook stub 生成器：
    ///
    /// 反编译依据（village.exe，玩家对象 r14、主状态 +0x1D8、目标状态 +0x1DC、任务指针 +0x238、
    /// 输入对象 +0x240、浮标对象 +0x290/+0x2A0、场景对象 +0x2C8）：
    ///
    ///   Hook C（续竿 / 自动重甩）：rva 0x216C9C 起 26 字节（resume 0x216CB6 `cmp qword[r14+0x238],rbx`）
    ///     覆盖：movsd xmm0,[rsp+0x50](6B, F2 0F 10 44 24 50)
    ///           → movsd [r14+0x2A8],xmm0(9B, F2 41 0F 11 86 A8 02 00 00，REX 在前缀组最后)
    ///           → mov dword[r14+0x1DC],1(11B, 41 C7 86 DC 01 00 00 01 00 00 00)。
    ///     这是 state5（0x216BFB 收竿动画）播完后的续竿点：原版写 1 回 state1“继续等/咬钩”。
    ///     超时重甩路径也汇合于此：state2 等咬钩超时 → [1DC]=5 → state5 收竿动画 → 0x216CAB 续竿点，
    ///     因此无需单独 hook 0x215E0A（其 10 字节不足 detour 且 0x215DF7 `je 0x215e0a` 直接跳入不可前扩）。
    ///     自动判定：gEnabled==1 且 gBagFull==0 → 写 0 回 state0 重新甩竿（刷新浮标位置，实现自动循环）；
    ///     否则写 1 走原版（F8 关闭 / 背包已满 / 玩家按收杆键时 state1 原版 0x497→[1DC]=7 手动收杆自然停止）。
    ///
    ///   Hook D（入包 / 背包满检测）：rva 0x216B46 起 45 字节（state4 结算入包调用点，0x216A73 jmp 0x216B46 两路汇合，
    ///     resume 0x216B73 `mov rax,[r13]`）：
    ///     mov rax,[rip+0xEC8F83]（全局单例 0x10DFAD0 内容）→ mov rcx,[rax+0x208]（持有物容器）→
    ///     mov byte[rsp+0x20],1 → xor r9d,r9d → mov edx,0x41A → mov r8d,6 → mov rcx,[rcx+0x32B8]（背包容器）→
    ///     call 0x138BC0（持有物添加 + 容量判定）。
    ///     0x138BC0 满路径（0x138DF5-0x138E13）：clamp 后发消息 0x3EB（“背包已满”提示）并 xor al,al 返回 0；
    ///     成功路径 mov al,1。stub 复放该调用并在返回后检查 al：
    ///       al==0 且自动模式 → gBagFull=1（停续竿、加载器提示）；
    ///       al==1 且自动模式 → gFishCount++ 且 gBagFull=0（清包后自动恢复自动循环）。
    ///   注意：续竿 stub 内不做 0x497 按键查询——state1 原版已能捕获收杆键（0x215743），
    ///   且 stub 内调用 0x7EF810 需预先构造输入描述结构（0x2156EA-0x21573B 含 0xE587C0/0xA13B06 指针）
    ///   并伴随 `inc [输入实例+0xBC]` 副作用，故不采纳。
    /// </summary>
    internal static class CastHookStub
    {
        /// <summary>
        /// Hook C：续竿 / 自动重甩 stub，写入 buf[offset, offset+~140)。
        /// 使用 HookStub.Emitter 生成，只使用易失寄存器（rax/rcx/rdx/r8-r11），保留 r14/rbx 等非易失寄存器供 resume 使用。
        /// </summary>
        /// <param name="buf">目标进程 stub 缓冲区（HookStub.Build 写好整体后调用）。</param>
        /// <param name="offset">本 stub 在缓冲区内的偏移（HookStub.CastStubOffset）。</param>
        /// <param name="moduleBase">模块基址（= target − HookRva）。</param>
        /// <param name="flagEnabled">gEnabled 绝对地址。</param>
        /// <param name="flagBagFull">gBagFull 绝对地址。</param>
        public static void BuildCast(byte[] buf, int offset, long moduleBase,
            long flagEnabled, long flagBagFull)
        {
            long resume = moduleBase + HookStub.CastResumeRva;
            var em = new HookStub.Emitter();

            // ---- 复放被覆盖的原始指令 ----
            // 0x216C9C movsd xmm0,[rsp+0x50]（6B：F2 0F 10 44 24 50）
            // 0x216CA2 movsd [r14+0x2A8],xmm0（9B：F2 41 0F 11 86 A8 02 00 00，REX 在前缀组最后）
            em.Bytes(0xF2, 0x0F, 0x10, 0x44, 0x24, 0x50);                     // movsd xmm0,[rsp+0x50]
            em.Bytes(0xF2, 0x41, 0x0F, 0x11, 0x86, 0xA8, 0x02, 0x00, 0x00);   // movsd [r14+0x2A8],xmm0

            // ---- 判定1：gEnabled==0 → 写 1（原版续竿） ----
            em.MovAbsR11(flagEnabled);
            em.Bytes(0x41, 0x80, 0x3B, 0x00);                                 // cmp byte [r11], 0
            em.Jcc8(0x74, "writeOne");                                        // je writeOne

            // ---- 判定2：gBagFull==1 → 写 1（原版续竿，等待玩家手动收杆清包） ----
            em.MovAbsR11(flagBagFull);
            em.Bytes(0x41, 0x80, 0x3B, 0x00);                                 // cmp byte [r11], 0
            em.Jcc8(0x75, "writeOne");                                        // jne writeOne

            // ---- 自动模式：写 0 → 回 state0 重新甩竿（包含超时重甩） ----
            em.Bytes(0x41, 0xC7, 0x86, 0xDC, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00);                                 // mov dword [r14+0x1DC], 0
            em.Bytes(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);                     // jmp qword [rip+0]
            int resumeSlot0 = em.Pos;
            em.Bytes(0, 0, 0, 0, 0, 0, 0, 0);

            // ---- 原版路径：写 1（state5 收竿动画完成回 state1） ----
            em.Label("writeOne");
            em.Bytes(0x41, 0xC7, 0x86, 0xDC, 0x01, 0x00, 0x00,
                     0x01, 0x00, 0x00, 0x00);                                 // mov dword [r14+0x1DC], 1
            em.Bytes(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);                     // jmp qword [rip+0]
            int resumeSlot1 = em.Pos;
            em.Bytes(0, 0, 0, 0, 0, 0, 0, 0);

            byte[] code = em.Finish();
            var slots = em.Imm64Slots;                                        // 0=&gEnabled 1=&gBagFull
            HookStub.WriteImm(code, slots[0], (ulong)flagEnabled);
            HookStub.WriteImm(code, slots[1], (ulong)flagBagFull);
            HookStub.WriteImm(code, resumeSlot0, (ulong)resume);
            HookStub.WriteImm(code, resumeSlot1, (ulong)resume);
            Array.Copy(code, 0, buf, offset, code.Length);
        }

        /// <summary>
        /// Hook D：入包 / 背包满检测 stub，写入 buf[offset, offset+~190)。
        /// 复放完整入包调用（含绝对地址 call 0x138BC0），返回后按 al 更新 gBagFull/gFishCount。
        /// 使用 HookStub.Emitter 生成，只使用易失寄存器（rax/rcx/rdx/r8/r9/r11），保留 r13 供 resume `mov rax,[r13]` 使用。
        /// </summary>
        /// <param name="buf">目标进程 stub 缓冲区（HookStub.Build 写好整体后调用）。</param>
        /// <param name="offset">本 stub 在缓冲区内的偏移（HookStub.BagStubOffset）。</param>
        /// <param name="moduleBase">模块基址（= target − HookRva）。</param>
        /// <param name="flagEnabled">gEnabled 绝对地址。</param>
        /// <param name="flagBagFull">gBagFull 绝对地址。</param>
        /// <param name="flagFishCount">gFishCount 绝对地址。</param>
        public static void BuildBag(byte[] buf, int offset, long moduleBase,
            long flagEnabled, long flagBagFull, long flagFishCount)
        {
            long resume = moduleBase + HookStub.BagResumeRva;
            long global = moduleBase + HookStub.GlobalRva;
            long addHold = moduleBase + HookStub.AddHoldRva;
            var em = new HookStub.Emitter();

            // ---- 复放入包调用：rax = *(0x10DFAD0)；rcx=[rax+0x208]；参数 & call 0x138BC0 ----
            em.MovAbsR11(global);                                              // movabs r11, &全局变量地址
            em.Bytes(0x49, 0x8B, 0x03);                                        // mov rax, [r11]          ← 读取全局单例内容
            em.Bytes(0x48, 0x8B, 0x88, 0x08, 0x02, 0x00, 0x00);                // mov rcx, [rax+0x208]
            em.Bytes(0xC6, 0x44, 0x24, 0x20, 0x01);                            // mov byte [rsp+0x20], 1
            em.Bytes(0x45, 0x33, 0xC9);                                        // xor r9d, r9d（原编码 45 33 C9）
            em.Bytes(0xBA, 0x1A, 0x04, 0x00, 0x00);                            // mov edx, 0x41A
            em.Bytes(0x41, 0xB8, 0x06, 0x00, 0x00, 0x00);                      // mov r8d, 6
            em.Bytes(0x48, 0x8B, 0x89, 0xB8, 0x32, 0x00, 0x00);                // mov rcx, [rcx+0x32B8]
            em.MovAbsR11(addHold);                                             // movabs r11, &0x138BC0
            em.Bytes(0x41, 0xFF, 0xD3);                                        // call r11
            em.Bytes(0x84, 0xC0);                                              // test al, al
            em.Jcc8(0x75, "ok");                                               // jnz ok（成功入包）

            // ---- 满路径（al==0）：自动模式置 gBagFull=1 ----
            em.MovAbsR11(flagEnabled);
            em.Bytes(0x41, 0x80, 0x3B, 0x00);                                  // cmp byte [r11], 0
            em.Jcc8(0x74, "resume");                                           // je resume（未开自动，原样）
            em.MovAbsR11(flagBagFull);
            em.Bytes(0x41, 0xC6, 0x03, 0x01);                                  // mov byte [r11], 1
            em.Jcc8(0xEB, "resume");                                           // jmp resume

            // ---- 成功路径（al==1）：gFishCount++ 且 gBagFull 清 0（清包后自动恢复） ----
            em.Label("ok");
            em.MovAbsR11(flagEnabled);
            em.Bytes(0x41, 0x80, 0x3B, 0x00);                                  // cmp byte [r11], 0
            em.Jcc8(0x74, "resume");                                           // je resume
            em.MovAbsR11(flagFishCount);
            em.Bytes(0x41, 0xFF, 0x03);                                        // inc dword [r11]  ← 已钓条数++
            em.MovAbsR11(flagBagFull);
            em.Bytes(0x41, 0xC6, 0x03, 0x00);                                  // mov byte [r11], 0

            // ---- 汇合：跳回 resume ----
            em.Label("resume");
            em.Bytes(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);                      // jmp qword [rip+0]
            int resumeSlot = em.Pos;
            em.Bytes(0, 0, 0, 0, 0, 0, 0, 0);

            byte[] code = em.Finish();
            var slots = em.Imm64Slots;   // 0=&global 1=&addHold 2=&gEnabled 3=&gBagFull 4=&gEnabled 5=&gFishCount 6=&gBagFull
            HookStub.WriteImm(code, slots[0], (ulong)global);
            HookStub.WriteImm(code, slots[1], (ulong)addHold);
            HookStub.WriteImm(code, slots[2], (ulong)flagEnabled);
            HookStub.WriteImm(code, slots[3], (ulong)flagBagFull);
            HookStub.WriteImm(code, slots[4], (ulong)flagEnabled);
            HookStub.WriteImm(code, slots[5], (ulong)flagFishCount);
            HookStub.WriteImm(code, slots[6], (ulong)flagBagFull);
            HookStub.WriteImm(code, resumeSlot, (ulong)resume);
            Array.Copy(code, 0, buf, offset, code.Length);
        }
    }
}