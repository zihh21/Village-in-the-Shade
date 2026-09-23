using System;
using System.Collections.Generic;

namespace FishingAutoCatch
{
    /// <summary>
    /// 钓鱼自动收杆（跳过"鱼上钩拉线节奏小游戏"）的核心 Hook 机器码生成器。
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
    /// 热键说明（v0.3.0 起）：F8 不再由 stub 轮询（原方案存在 call Beep 破坏 rax 的缺陷），
    /// 改由加载器（监控进程）内 GetAsyncKeyState(VK_F8) 轮询——该 API 在任何进程都反映全局键盘状态，
    /// 因此任意时刻（含非钓鱼场景）都能切换开关，切换时加载器侧 Beep 发声提示。
    ///
    /// 诊断：每次真正执行"自动判定"时递增 gHits 计数（供加载器显示，便于确认 Hook 生效）。
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

        // ---------------- 注入缓冲区布局（代码 164 + 状态字节） ----------------
        /// <summary>gEnabled：开关（加载器侧 F8 翻转）。</summary>
        public const int FlagEnabledOffset = 164;
        /// <summary>gHits(dword)：自动判定累计触发次数（诊断）。</summary>
        public const int FlagHitsOffset = 165;
        public const int StubBufferSize = 170;

        /// <summary>
        /// 生成完整 stub 代码（跳转与 64 位立即数已回填）。
        /// </summary>
        /// <param name="stubBase">注入缓冲区在目标进程内的基址。</param>
        /// <param name="target">Hook 目标函数地址（模块基址 + HookRva）。</param>
        public static byte[] Build(long stubBase, long target)
        {
            var em = new Emitter();
            long resume = target + PatchLength;               // 跳回 0x...A86F（push rbp 处）
            long flagEnabled = stubBase + FlagEnabledOffset;
            long flagHits = stubBase + FlagHitsOffset;

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
            return code;
        }

        private static void WriteImm(byte[] code, int pos, ulong v)
        {
            for (int i = 0; i < 8; i++) code[pos + i] = (byte)(v >> (8 * i));
        }

        /// <summary>极小 x64 汇编发射器：支持本 stub 所需指令与标签/跳转回填。</summary>
        private sealed class Emitter
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