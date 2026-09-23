using System;
using System.Collections.Generic;

namespace FishingAutoCatch
{
    /// <summary>
    /// 钓鱼自动收杆（跳过"鱼上钩拉线节奏小游戏"）的核心 Hook 机器码生成器。
    ///
    /// 反编译依据（village.exe，ImageBase 0x140000000）：
    ///   Hook 点：rva 0x38A860 = CTask_Menu_Fishing::update 的节奏判定入口（经 0x388DD0 stubb 被任务 ctor 0x388B30 注册）。
    ///   对象布局（this = CTask_Menu_Fishing*）：
    ///     +0x248 byte  完成标志（0=进行中，成功后置 1，见 0x38B310）
    ///     +0x250 qword 音符数组起始指针（元素 8 字节：{float 时间, int 状态}）
    ///     +0x258 qword 音符数组结束指针
    ///     +0x268 dword 当前判定索引（每次处理后 +1，见 0x38B2E0）
    ///     +0x240 qword 场景对象指针；[[this+0x240]+0x20]+0x568 == 0x3F2 时处于"已咬钩、节奏小游戏运行中"（见 0x38A9D7）
    ///   音符状态：0=未激活, 1=可击, 2=命中, 3=漏击（漏击永不成功——鱼儿跑掉的来源）
    ///   音符总数 = ([+0x258] - [+0x250]) &gt;&gt; 3
    ///
    /// 自动成功原理：
    ///   0x38B114 汇合点：`cmp [this+0x268], 总数; jge 0x38B2E6`。
    ///   只要入口处把所有音符 state 置 2、并把 [this+0x268] 置为总数，
    ///   同一帧内（无论是否按键）就会走到成功检查 0x38B2E6 → 置完成标志 →
    ///   0x38B330 全音符==2 检查通过 → 0x38B343 发"钓鱼成功"事件（rva 0xE354E0）与消息 0xFB。
    ///   该路径与自然打完所有音符时完全一致，鱼获按正规流程结算，不修改品质/数量。
    ///
    /// 热键：F8（0x77）。进程内通过 GetAsyncKeyState 探测沿触发，切换全局启用开关。
    ///   注入后默认开启；stub 内嵌两个状态字节（gEnabled / gLastF8）。
    /// </summary>
    internal static class HookStub
    {
        // ---------------- 反编译结论常量化 ----------------
        /// <summary>Hook 目标 rva：节奏判定函数入口。</summary>
        public const long HookRva = 0x38A860L;
        /// <summary>覆盖字节数：mov rax,rsp(3) + mov[rax+10],rbx(4) + mov[rax+18],rsi(4) + mov[rax+20],rdi(4) = 15 字节。</summary>
        public const int PatchLength = 15;
        /// <summary>VK_F8。</summary>
        public const int VkF8 = 0x77;

        // ---------------- 注入缓冲区布局 ----------------
        /// <summary>stub 代码区之后的状态字节：gEnabled（注入时置 1＝开启）。</summary>
        public const int FlagEnabledOffset = 228;
        /// <summary>gLastF8：上次检测到的 F8 按下状态（沿触发用）。</summary>
        public const int FlagLastF8Offset = 229;
        public const int StubBufferSize = 230;

        /// <summary>
        /// 生成完整 stub 代码（含占位跳转与 64 位立即数槽位已填值）。
        /// </summary>
        /// <param name="stubBase">注入缓冲区在目标进程内的基址（stub 与状态字节所在内存）。</param>
        /// <param name="target">Hook 目标函数地址（模块基址 + HookRva）。</param>
        /// <param name="getAsyncKeyState">目标进程内 user32!GetAsyncKeyState 地址。</param>
        public static byte[] Build(long stubBase, long target, long getAsyncKeyState)
        {
            var em = new Emitter();
            long resume = target + PatchLength;               // 跳回 0x...A86F（push rbp 处）
            long flagEnabled = stubBase + FlagEnabledOffset;  // gEnabled 绝对地址
            long flagLastF8 = stubBase + FlagLastF8Offset;    // gLastF8  绝对地址

            // ---- 1) 保存 this（rcx），GetAsyncKeyState 会破坏易失寄存器 ----
            em.Bytes(0x51);                                    // push rcx

            // ---- 2) F8 沿触发：GetAsyncKeyState(VK_F8) 最高位=1 表示按下 ----
            em.MovAbsR10(getAsyncKeyState);                    // movabs r10, addr
            em.Bytes(0xB9, VkF8, 0x00, 0x00, 0x00);            // mov ecx, 0x77
            em.Bytes(0x41, 0xFF, 0xD2);                        // call r10
            em.Bytes(0x66, 0xA9, 0x00, 0x80);                  // test ax, 0x8000
            em.Jcc8(0x74, "noF8");                             // je noF8（未按下）
            em.MovAbsRax(flagLastF8);                          // movabs rax, &gLastF8
            em.Bytes(0x80, 0x38, 0x00);                        // cmp byte [rax], 0
            em.Jcc8(0x75, "hadPressed");                       // jne hadPressed（上次已按过→忽略）
            em.MovAbsRdx(flagEnabled);                         // movabs rdx, &gEnabled
            em.Bytes(0x80, 0x32, 0x01);                        // xor byte [rdx], 1  ←切换 开/关
            em.Bytes(0xC6, 0x00, 0x01);                        // mov byte [rax], 1（记按下）
            em.Jcc8(0xEB, "afterKey");
            em.Label("hadPressed");
            em.Bytes(0xC6, 0x00, 0x01);                        // mov byte [rax], 1（保持按下标记）
            em.Jcc8(0xEB, "afterKey");
            em.Label("noF8");
            em.MovAbsRax(flagLastF8);                          // movabs rax, &gLastF8
            em.Bytes(0xC6, 0x00, 0x00);                        // mov byte [rax], 0（记松开）
            em.Label("afterKey");
            em.Bytes(0x59);                                    // pop rcx（恢复 this）

            // ---- 3) 开关检查：关闭 → 直接走原逻辑 ----
            em.MovAbsRax(flagEnabled);                         // movabs rax, &gEnabled
            em.Bytes(0x80, 0x38, 0x00);                        // cmp byte [rax], 0
            em.Jcc8(0x74, "trampoline");                       // je trampoline

            // ---- 4) 守卫：任务未完成（[this+0x248]==0，对应原入口 0x38A8BD 检查） ----
            em.Bytes(0x80, 0xB9, 0x48, 0x02, 0x00, 0x00, 0x00); // cmp byte [rcx+0x248], 0
            em.Jcc8(0x75, "trampoline");                       // jne trampoline

            // ---- 5) 守卫：音符数组有效且非空 ----
            em.MovRaxRcxOff(0x250);                            // mov rax, [rcx+0x250]
            em.Bytes(0x48, 0x85, 0xC0);                        // test rax, rax
            em.Jcc8(0x74, "trampoline");                       // je trampoline
            em.MovRdxRcxOff(0x258);                            // mov rdx, [rcx+0x258]
            em.Bytes(0x48, 0x29, 0xC2);                        // sub rdx, rax
            em.Bytes(0x48, 0xC1, 0xFA, 0x03);                  // sar rdx, 3   ←音符总数
            em.Bytes(0x85, 0xD2);                              // test edx, edx
            em.Jcc8(0x7E, "trampoline");                       // jle trampoline（无音符）

            // ---- 6) 守卫：对象状态 [[this+0x240]+0x20]+0x568==0x3F2（已咬钩进入节奏小游戏） ----
            em.MovRaxRcxOff(0x240);                            // mov rax, [rcx+0x240]
            em.Bytes(0x48, 0x85, 0xC0);                        // test rax, rax
            em.Jcc8(0x74, "trampoline");                       // je trampoline
            em.Bytes(0x48, 0x8B, 0x40, 0x20);                  // mov rax, [rax+0x20]
            em.Bytes(0x48, 0x85, 0xC0);                        // test rax, rax
            em.Jcc8(0x74, "trampoline");                       // je trampoline
            em.Bytes(0x81, 0xB8, 0x68, 0x05, 0x00, 0x00,
                     0xF2, 0x03, 0x00, 0x00);                  // cmp dword [rax+0x568], 0x3F2
            em.Jcc8(0x75, "trampoline");                       // jne trampoline

            // ---- 7) 全部音符置 state=2（命中） ----
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

            // ---- 8) 复放被覆盖的原始 prologue，跳回原函数继续执行 ----
            em.Label("trampoline");
            em.Bytes(0x48, 0x8B, 0xC4);                        // mov rax, rsp
            em.Bytes(0x48, 0x89, 0x58, 0x10);                  // mov [rax+0x10], rbx
            em.Bytes(0x48, 0x89, 0x70, 0x18);                  // mov [rax+0x18], rsi
            em.Bytes(0x48, 0x89, 0x78, 0x20);                  // mov [rax+0x20], rdi
            em.Bytes(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);      // jmp qword ptr [rip+0]
            int resumeSlot = em.Pos;
            em.Bytes(0, 0, 0, 0, 0, 0, 0, 0);                  // 8 字节绝对地址槽（resume）

            byte[] code = em.Finish();
            var slots = em.Imm64Slots;                       // 5 个 64 位地址槽（按生成顺序）

            WriteImm(code, slots[0], (ulong)getAsyncKeyState);
            WriteImm(code, slots[1], (ulong)flagLastF8);
            WriteImm(code, slots[2], (ulong)flagEnabled);
            WriteImm(code, slots[3], (ulong)flagLastF8);
            WriteImm(code, slots[4], (ulong)flagEnabled);
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

            public void MovAbsR10(long v) => EmitMovAbs(0x49, 0xBA, v);
            public void MovAbsRax(long v) => EmitMovAbs(0x48, 0xB8, v);
            public void MovAbsRdx(long v) => EmitMovAbs(0x48, 0xBA, v);

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