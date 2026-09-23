using System;
using System.Collections.Generic;

namespace FishingAutoCatch
{
    /// <summary>
    /// 钓鱼自动循环（FishingAutoCatch v1.0.0）的核心 Hook 机器码生成器。
    ///
    /// 反编译依据（village.exe，ImageBase 0x140000000）：
    ///   Hook 点 A：rva 0x38A860 = CTask_Menu_Fishing::update 节奏判定入口（经 0x388DD0 stub 被任务 ctor 0x388B30 注册）。
    ///   对象布局（this = CTask_Menu_Fishing*）：
    ///     +0x240 qword 场景对象指针；[[this+0x240]+0x20]+0x568 == 0x3F2 时处于"已咬钩、节奏小游戏运行中"（见 0x38A9D7）
    ///     +0x248 byte  完成标志（0=进行中，成功后置 1，见 0x38B310）
    ///     +0x250 qword 音符数组起始指针（元素 8 字节：{float 时间, int 状态}）
    ///     +0x258 qword 音符数组结束指针
    ///     +0x268 dword 当前判定索引（每次处理后 +1，见 0x38B2E0）
    ///   音符状态：0=未激活, 1=可击, 2=命中, 3=漏击（漏击永不成功——鱼儿跑掉的来源）
    ///   音符总数 = ([+0x258] - [+0x250]) &gt;&gt; 3
    ///
    ///   Hook 点 B（配合点）：rva 0x38B2FB = `test al,al` + rva 0x38B2FD = `0F 84 81 01 00 00`
    ///     （je rel32 → 0x38B484 成功动作出口）。0x38B2F6 调用 0x7491b0（通用"时间轴播完"判定），
    ///     返回值 al 为 0 时跳到 0x38B484 直接退出本帧——这就是"伪造音符全命中仍卡在小游戏"的原因：
    ///     时间线内部事件（[<时间轴>+0x8d0] 树）不会因为我们把音符置 2 而标记完成，0x7491b0 恒返回 0。
    ///     因此把该 je 替换为 6 字节 NOP：音符达标（index &gt;= 总数）后无条件执行 0x38B303 起的成功动作
    ///     （置完成标志 → 全音符==2 检查 → 0x38B343 发成功事件 rva 0xE354E0 + 消息 0xFB），
    ///     仍与手动通关同一条正规结算路径。
    ///
    ///   Hook 点 C（续竿 / 自动重甩）：rva 0x216C9C 起 26 字节，属于玩家主状态机"钓鱼状态"（玩家对象 r14，
    ///     +0x1DC 为目标状态、+0x238 任务指针、+0x240 输入对象、+0x2A8 浮标位置 float）。
    ///     state5（0x216BFB 收竿动画）动画播完走到 0x216C9C-0x216CB5：
    ///       movsd xmm0,[rsp+0x50]（6B）→ movsd [r14+0x2A8],xmm0（9B，含 REX.B 前缀 0x41）→
    ///       mov [r14+0x1DC],1（11B）=26B，
    ///     原版写 1 回 state1（等待/继续等咬钩）。自动模式下改写 0 回 state0 重新甩竿（刷新浮标位置），
    ///     同时覆盖"state2 等咬钩超时 → [1DC]=5 → state5 收竿动画 → 续竿点"的超时重甩路径，无需单独 hook 0x215E0A。
    ///     判定：gEnabled==0 或 gBagFull==1 → 写 1 走原版（F8 关闭 / 背包已满，等玩家手动收杆清包）；
    ///     否则写 0 自动续竿重甩。收杆键由 state1 原版检测（0x497 → [1DC]=7 手动收杆自然停止），stub 内不查键。
    ///
    ///   Hook 点 D（背包满检测 / 入包计数）：rva 0x216B46 起 45 字节（state4 结算入包调用点，两路汇合 0x216A73 jmp 0x216B46）：
    ///     mov rax,[rip+0xEC8F83]（全局单例 0x10DFAD0 内容）+ mov rcx,[rax+0x208] + mov byte [rsp+0x20],1 +
    ///     xor r9d,r9d + mov edx,0x41A + mov r8d,6 + mov rcx,[rcx+0x32B8]（背包容器）+ call 0x138BC0（持有物添加，resume 0x216B73 mov rax,[r13]）。
    ///     0x138BC0 内部容量判定（0x138DF5-0x138E13）：满时 clamp 后发消息 0x3EB（通用"无法持有/已满"）并 xor al,al 返回 0，
    ///     正常路径（0x138ED3→0x1390C2）mov al,1。stub 复放调用后读 al：
    ///     al==0 且自动模式 → gBagFull=1（停续竿）；al==1 → gFishCount++ 且 gBagFull=0（清包后自动恢复）。
    ///
    /// 热键说明（v0.3.0 起）：F8 不再由 stub 轮询（原方案存在 call Beep 破坏 rax 的缺陷），
    /// 改由加载器（监控进程）内 GetAsyncKeyState(VK_F8) 轮询——该 API 在任何进程都反映全局键盘状态，
    /// 因此任意时刻（含非钓鱼场景）都能切换开关，切换时加载器侧 Beep 发声提示。
    ///
    /// 诊断：每次真正执行"自动判定"时递增 gHits 计数；每成功入包一次递增 gFishCount（供加载器显示"本次已钓 N 条"）。
    /// </summary>
    internal static class HookStub
    {
        // ---------------- 反编译结论常量化 ----------------
        /// <summary>Hook 点 A：节奏判定函数入口。</summary>
        public const long HookRva = 0x38A860L;
        /// <summary>覆盖字节数：mov rax,rsp(3) + mov[rax+10],rbx(4) + mov[rax+18],rsi(4) + mov[rax+20],rdi(4) = 15 字节。</summary>
        public const int PatchLength = 15;

        /// <summary>Hook 点 B：成功后置（0x38B2FD `je 0x38B484`，6 字节），替换为 NOP。</summary>
        public const long SuccessRva = 0x38B2FDL;
        public const int SuccessPatchLength = 6;
        /// <summary>0F 84 81 01 00 00 → 6×0x90（跳过 0x7491b0 结果，无条件进入成功动作）。</summary>
        public static readonly byte[] SuccessPatch = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

        // ---------------- Hook 点 C：续竿 / 自动重甩（v1.0.0 新增） ----------------
        /// <summary>
        /// Hook 点 C：state5 收竿动画完成点（resume 0x216CB6，覆盖 0x216C9C..0x216CB5 = 26 字节）：
        ///   0x216C9C movsd xmm0,[rsp+0x50]（6B，F2 0F 10 44 24 50）
        ///   0x216CA2 movsd [r14+0x2A8],xmm0（9B，41 F2 0F 11 86 A8 02 00 00，REX.B 前缀 0x41 针对 r14）
        ///   0x216CAB mov dword [r14+0x1DC],1（11B，41 C7 86 DC 01 00 00 01 00 00 00）
        ///   0x216CB6 resume：cmp qword [r14+0x238],rbx
        /// </summary>
        public const long CastRva = 0x216C9CL;
        public const int CastPatchLength = 26;
        public const long CastResumeRva = 0x216CB6L;

        // ---------------- Hook 点 D：背包满检测 / 入包计数（v1.0.0 新增） ----------------
        /// <summary>Hook 点 D：入包调用点（state4 结算，45 字节，resume 0x216B73）。</summary>
        public const long BagRva = 0x216B46L;
        public const int BagPatchLength = 45;
        public const long BagResumeRva = 0x216B73L;
        /// <summary>持有物添加函数（容量判定，返回 al=0 满 / al=1 成功）。</summary>
        public const long AddHoldRva = 0x138BC0L;
        /// <summary>输入查询：rcx=输入对象、edx=键ID、r8=查询结构；返回 al=1 激活/按下。</summary>
        public const long InputQueryRva = 0x7EF810L;
        /// <summary>收杆键键值（state1 原版检测 0x497 → [1DC]=7 手动收杆）。</summary>
        public const int CastKeyId = 0x497;
        /// <summary>全局单例（内容为持有物/关系容器，+0x208 持有物容器、+0x208+0x32B8 背包容器）。</summary>
        public const long GlobalRva = 0x10DFAD0L;

        // ---------------- 注入缓冲区布局（代码区 + 查询结构区 + 状态字节） ----------------
        /// <summary>续竿 stub 起点（Hook A 区结束后向 16 对齐）。</summary>
        public const int CastStubOffset = 176;
        /// <summary>入包 stub 起点（续竿 stub 结束后向 16 对齐，预留 192 字节空间）。</summary>
        public const int BagStubOffset = 368;
        /// <summary>状态区起点：gEnabled(1B) + gHits(4B) + gBagFull(1B) + gFishCount(4B) + 三口入口计数(4B×3)。</summary>
        public const int FlagsOffset = 560;
        /// <summary>gEnabled：自动模式总开关（F8）。</summary>
        public const int FlagEnabledOffset = FlagsOffset + 0;
        /// <summary>gHits(dword)：自动判定累计触发次数（诊断）。</summary>
        public const int FlagHitsOffset = FlagsOffset + 1;
        /// <summary>gBagFull(byte)：游戏真实背包已满（0x138BC0 返回 0 时置位，入包成功清 0）。</summary>
        public const int FlagBagFullOffset = FlagsOffset + 5;
        /// <summary>gFishCount(dword)：本次自动循环成功入包条数。</summary>
        public const int FlagFishCountOffset = FlagsOffset + 6;
        /// <summary>gEntryA(dword)：Hook A（0x38A860）入口被执行次数（无条件计数，v1.0.2 诊断用）。</summary>
        public const int FlagEntryAOffset = FlagsOffset + 10;
        /// <summary>gEntryC(dword)：Hook C（0x216C9C）入口被执行次数（无条件计数，v1.0.2 诊断用）。</summary>
        public const int FlagEntryCOffset = FlagsOffset + 14;
        /// <summary>gEntryD(dword)：Hook D（0x216B46）入口被执行次数（无条件计数，v1.0.2 诊断用）。</summary>
        public const int FlagEntryDOffset = FlagsOffset + 18;
        /// <summary>总缓冲区：Hook A(≤176) + Hook C(≤192) + Hook D(≤192) + Flags(22)。</summary>
        public const int StubBufferSize = 640;

        /// <summary>
        /// 生成完整 stub 缓冲区（跳转与 64 位立即数已回填）。
        /// 布局：[0,176)  Hook A 节奏判定 → [176,368) Hook C 续竿/重甩 → [368,560) Hook D 入包/背包满 → [560,640) 状态区。
        /// 状态区固定偏移由注入器初始化（gEnabled/gHits/gBagFull/gFishCount）。
        /// </summary>
        /// <param name="stubBase">注入缓冲区在目标进程内的基址。</param>
        /// <param name="target">Hook A 目标函数地址（模块基址 + HookRva）。</param>
        public static byte[] Build(long stubBase, long target)
        {
            long moduleBase = target - HookRva;
            var buf = new byte[StubBufferSize];
            long flagEnabled = stubBase + FlagEnabledOffset;
            long flagHits = stubBase + FlagHitsOffset;
            long flagBagFull = stubBase + FlagBagFullOffset;
            long flagFishCount = stubBase + FlagFishCountOffset;

            BuildHookA(buf, moduleBase, flagEnabled, flagHits);
            CastHookStub.BuildCast(buf, CastStubOffset, moduleBase, flagEnabled, flagBagFull);
            CastHookStub.BuildBag(buf, BagStubOffset, moduleBase, flagEnabled, flagBagFull, flagFishCount);
            return buf;
        }

        /// <summary>Hook A：节奏小游戏自动判定 stub，写入 buf[0, CastStubOffset)。</summary>
        private static void BuildHookA(byte[] buf, long moduleBase, long flagEnabled, long flagHits)
        {
            long resume = moduleBase + HookRva + PatchLength;   // 跳回 0x...A86F（push rbp 处）
            var em = new Emitter();

            // ---- 0) 无条件入口计数（v1.0.2 诊断）：无论开关状态，只要游戏执行到 0x38A860 就 +1 ----
            //       用于判定"游戏是否真的到达节奏判定函数"（此前用户反馈全失效，需客观区分 未执行/守卫不过/开关未开）。
            em.EmitEntryInc(0, FlagEntryAOffset);               // inc dword [rip+disp32] ← gEntryA

            // ---- 1) 开关检查：关闭 → 直接走原逻辑 ----
            em.MovAbsRax(flagEnabled);                         // movabs rax, &gEnabled
            em.Bytes(0x80, 0x38, 0x00);                        // cmp byte [rax], 0
            em.Jcc8(0x74, "trampoline");                       // je trampoline

            // ---- 2) 守卫：任务未完成（[this+0x248]==0） ----
            em.Bytes(0x80, 0xB9, 0x48, 0x02, 0x00, 0x00, 0x00); // cmp byte [rcx+0x248], 0
            em.Jcc8(0x75, "trampoline");                       // jne trampoline

            // ---- 3) 守卫：音符数组有效且非空 ----
            em.MovRaxRcxOff(0x250);                            // mov rax, [rcx+0x250]
            em.Bytes(0x48, 0x85, 0xC0);                        // test rax, rax
            em.Jcc8(0x74, "trampoline");                       // je trampoline
            em.MovRdxRcxOff(0x258);                            // mov rdx, [rcx+0x258]
            em.Bytes(0x48, 0x29, 0xC2);                        // sub rdx, rax
            em.Bytes(0x48, 0xC1, 0xFA, 0x03);                  // sar rdx, 3   ←音符总数
            em.Bytes(0x85, 0xD2);                              // test edx, edx
            em.Jcc8(0x7E, "trampoline");                       // jle trampoline（无音符）

            // ---- 4) 守卫：对象状态 [[this+0x240]+0x20]+0x568==0x3F2（已咬钩进入节奏小游戏） ----
            em.MovRaxRcxOff(0x240);                            // mov rax, [rcx+0x240]
            em.Bytes(0x48, 0x85, 0xC0);                        // test rax, rax
            em.Jcc8(0x74, "trampoline");                       // je trampoline
            em.Bytes(0x48, 0x8B, 0x40, 0x20);                  // mov rax, [rax+0x20]
            em.Bytes(0x48, 0x85, 0xC0);                        // test rax, rax
            em.Jcc8(0x74, "trampoline");                       // je trampoline
            em.Bytes(0x81, 0xB8, 0x68, 0x05, 0x00, 0x00,
                     0xF2, 0x03, 0x00, 0x00);                  // cmp dword [rax+0x568], 0x3F2
            em.Jcc8(0x75, "trampoline");                       // jne trampoline

            // ---- 5) 全部音符置 state=2（命中） ----
            em.MovR8RcxOff(0x250);                             // mov r8, [rcx+0x250]
            em.Bytes(0x45, 0x31, 0xC9);                        // xor r9d, r9d   ← i=0
            em.Label("loop");
            em.Bytes(0x49, 0x39, 0xD1);                        // cmp r9, rdx
            em.Jcc8(0x7D, "setIndex");                         // jge setIndex
            em.Bytes(0x43, 0xC7, 0x44, 0xC8, 0x04,
                     0x02, 0x00, 0x00, 0x00);                  // mov dword [r8+r9*8+4], 2
            em.Bytes(0x49, 0xFF, 0xC1);                        // inc r9
            em.Jcc8(0xEB, "loop");
            em.Label("setIndex");
            em.Bytes(0x89, 0x91, 0x68, 0x02, 0x00, 0x00);      // mov [rcx+0x268], edx ←索引=总数
            em.MovAbsR11(flagHits);                            // movabs r11, &gHits
            em.Bytes(0x41, 0xFF, 0x03);                        // inc dword [r11] ←诊断计数

            // ---- 6) 复放被覆盖的原始 prologue，跳回原函数继续执行 ----
            em.Label("trampoline");
            em.Bytes(0x48, 0x8B, 0xC4);                        // mov rax, rsp
            em.Bytes(0x48, 0x89, 0x58, 0x10);                  // mov [rax+0x10], rbx
            em.Bytes(0x48, 0x89, 0x70, 0x18);                  // mov [rax+0x18], rsi
            em.Bytes(0x48, 0x89, 0x78, 0x20);                  // mov [rax+0x20], rdi
            em.Bytes(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);      // jmp qword ptr [rip+0]
            int resumeSlot = em.Pos;
            em.Bytes(0, 0, 0, 0, 0, 0, 0, 0);                  // 8 字节绝对地址槽（resume）

            byte[] code = em.Finish();
            var slots = em.Imm64Slots;                         // 按生成顺序：0=&gEnabled 1=&gHits

            WriteImm(code, slots[0], (ulong)flagEnabled);
            WriteImm(code, slots[1], (ulong)flagHits);
            WriteImm(code, resumeSlot, (ulong)resume);
            Array.Copy(code, 0, buf, 0, code.Length);
        }

        internal static void WriteImm(byte[] code, int pos, ulong v)
        {
            for (int i = 0; i < 8; i++) code[pos + i] = (byte)(v >> (8 * i));
        }

        /// <summary>极小 x64 汇编发射器：支持本 stub 所需指令与标签/跳转回填。</summary>
        internal sealed class Emitter
        {
            private readonly List<byte> _b = new List<byte>();
            private readonly Dictionary<string, int> _labels = new Dictionary<string, int>();
            private readonly List<(int pos, string label)> _jumps = new List<(int, string)>();
            private readonly List<int> _imm = new List<int>();

            public int Pos => _b.Count;
            /// <summary>64 位立即数槽位（发射顺序）。</summary>
            public List<int> Imm64Slots => _imm;

            public void Bytes(params int[] xs)
            {
                foreach (var x in xs) _b.Add((byte)x);
            }

            public void Label(string name) => _labels[name] = _b.Count;

            /// <summary>短跳转（rel8），op 为 0x74/0x75/0x7D/0x7E/0xEB。</summary>
            public void Jcc8(int op, string target)
            {
                _b.Add((byte)op);
                _b.Add(0);
                _jumps.Add((_b.Count - 1, target));
            }

            public void MovAbsRax(long v) => EmitMovAbs(0x48, 0xB8, v);
            public void MovAbsRdx(long v) => EmitMovAbs(0x48, 0xBA, v);
            public void MovAbsR11(long v) => EmitMovAbs(0x49, 0xBB, v);

            /// <summary>
            /// inc dword [rip+disp32]（6 字节 `FF 05` + disp32）：无条件递增入口计数 flag。
            /// disp32 通过"本条指令在 stub 缓冲区内的绝对偏移"计算，不占用 64 位立即数槽。
            /// </summary>
            /// <param name="bufferOffset">本 stub 在缓冲区内的起始偏移（Hook A=0 / C=CastStubOffset / D=BagStubOffset）。</param>
            /// <param name="targetStubOffset">目标 flag 在缓冲区内的偏移（如 FlagEntryAOffset）。</param>
            public void EmitEntryInc(int bufferOffset, int targetStubOffset)
            {
                int thisAbs = bufferOffset + _b.Count;        // 本条指令起点在缓冲区的位置
                int disp = targetStubOffset - (thisAbs + 6); // FF 05 disp32 指令长 6，disp 相对下一条
                _b.Add(0xFF);
                _b.Add(0x05);
                _b.Add((byte)disp);
                _b.Add((byte)(disp >> 8));
                _b.Add((byte)(disp >> 16));
                _b.Add((byte)(disp >> 24));
            }

            private void EmitMovAbs(int rex, int op, long v)
            {
                _b.Add((byte)rex);
                _b.Add((byte)op);
                _imm.Add(_b.Count);
                _b.AddRange(new byte[8]);
            }

            /// <summary>mov rax, [rcx+disp32]</summary>
            public void MovRaxRcxOff(int off) => Bytes(0x48, 0x8B, 0x81, off, off >> 8, off >> 16, off >> 24);

            /// <summary>mov rdx, [rcx+disp32]</summary>
            public void MovRdxRcxOff(int off) => Bytes(0x48, 0x8B, 0x91, off, off >> 8, off >> 16, off >> 24);

            /// <summary>mov r8, [rcx+disp32]</summary>
            public void MovR8RcxOff(int off) => Bytes(0x4C, 0x8B, 0x81, off, off >> 8, off >> 16, off >> 24);

            public byte[] Finish()
            {
                foreach (var (pos, label) in _jumps)
                {
                    int rel = _labels[label] - (pos + 1);
                    if (rel < sbyte.MinValue || rel > sbyte.MaxValue)
                        throw new InvalidOperationException($"跳转 {label} 超出 rel8 范围: {rel}");
                    _b[pos] = (byte)rel;
                }
                return _b.ToArray();
            }
        }
    }
}