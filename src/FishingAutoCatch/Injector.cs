using System;

namespace FishingAutoCatch
{
    /// <summary>
    /// 注入器：向目标进程分配内存写入 stub，并打两个 16 进制 patch：
    ///   Hook 点 A：0x38A860（CTask_Menu_Fishing::update 入口，15 字节）
    ///     覆盖字节（HookStub.PatchLength=15）：mov rax,rsp / mov[rax+10],rbx / mov[rax+18],rsi / mov[rax+20],rdi，
    ///     替换为 `FF 25 00000000 <stub基址8字节> 90`（jmp qword[rip+0] → stub）。
    ///     stub 末尾复放这 15 字节并跳回 target+15（0x...A86F push rbp 处）继续原函数执行。
    ///   Hook 点 B：0x38B2FD（成功检查 je 0x38B484，6 字节）
    ///     `0F 84 81 01 00 00` → 6×NOP。0x38B2F6 调用 0x7491b0（时间轴播完判定）返回 0 时会
    ///     跳到 0x38B484 退出本帧，导致"伪造音符全命中仍卡在小游戏"；NOP 后音符达标即无条件走成功动作。
    ///
    /// 状态字节（stub 缓冲区尾部，由注入器写入）：gEnabled(1B) + gHits(4B)。
    /// </summary>
    internal static class Injector
    {
        /// <summary>Hook A patch 头部：jmp [rip+0]（6 字节）＋8 字节绝对地址＋1 字节填充。</summary>
        private static readonly byte[] Signature = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };

        // ---------------- 安装 ----------------
        public static string Install(IntPtr hProcess, long moduleBase)
        {
            long targetA = moduleBase + HookStub.HookRva;
            long targetB = moduleBase + HookStub.SuccessRva;

            // 0) 防重复注入：若是本工具上次打的补丁，先还原为原始字节再重打
            RestoreIfDoubleInject(hProcess, moduleBase, targetA, targetB);

            // 1) 读取两处被覆盖前的原始字节（用于状态文件/还原）
            var originalA = new byte[HookStub.PatchLength];
            if (!ReadAt(hProcess, targetA, originalA))
                return "读取 Hook 点 A 原始字节失败（句柄权限不足？）。";
            var originalB = new byte[HookStub.SuccessPatchLength];
            if (!ReadAt(hProcess, targetB, originalB))
                return "读取 Hook 点 B 原始字节失败（句柄权限不足？）。";

            // 2) 在目标进程分配可执行内存
            IntPtr stubBasePtr = Win32Api.VirtualAllocEx(hProcess, IntPtr.Zero,
                new IntPtr(HookStub.StubBufferSize), Win32Api.MEM_COMMIT | Win32Api.MEM_RESERVE,
                Win32Api.PAGE_EXECUTE_READWRITE);
            if (stubBasePtr == IntPtr.Zero)
                return "VirtualAllocEx 失败（错误码 " + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + "）。";
            long stubBase = stubBasePtr.ToInt64();

            // 3) 生成并写入 stub 代码（绝对地址按 stubBase 回填）
            byte[] code = HookStub.Build(stubBase, targetA);
            if (!WriteAt(hProcess, stubBase, code))
                return "写入 stub 代码失败。";
            byte[] flags = { 0x01, 0x00, 0x00, 0x00, 0x00 }; // gEnabled=1(默认开启), gHits=0
            if (!WriteAt(hProcess, stubBase + HookStub.FlagEnabledOffset, flags))
                return "写入状态字节失败。";

            // 4) Hook A：入口 detour
            var patch = new byte[HookStub.PatchLength];
            Array.Copy(Signature, patch, Signature.Length);
            for (int i = 0; i < 8; i++) patch[6 + i] = (byte)((ulong)stubBase >> (8 * i));
            patch[14] = 0x90; // 填充（0x...A86E，原 prologue 末尾一字节）
            if (!ProtectWriteVerify(hProcess, targetA, patch))
                return "写入 detour（Hook A）失败或校验不一致。";

            // 5) Hook B：成功检查 je → NOP（跳过 0x7491b0 结果，无条件走成功动作）
            if (!ProtectWriteVerify(hProcess, targetB, HookStub.SuccessPatch))
                return "写入成功检查补丁（Hook B）失败或校验不一致。";

            // 6) 记录状态并返回
            PatchState.Save(moduleBase, stubBase, originalA, originalB);
            return $"注入成功。\n" +
                   $"  Hook A    : 0x{targetA:X}（入口 detour）\n" +
                   $"  Hook B    : 0x{targetB:X}（成功检查跳过）\n" +
                   $"  Stub 基址 : 0x{stubBase:X}\n" +
                   $"  默认开关  : 开启（加载器按 F8 切换，开启 880Hz/关闭 440Hz 提示音）";
        }

        /// <summary>若两个 Hook 点当前正是本模块上次写入的内容，则先还原原始字节并释放旧 stub，再让 Install 重打。</summary>
        private static void RestoreIfDoubleInject(IntPtr hProcess, long moduleBase, long targetA, long targetB)
        {
            if (!PatchState.TryLoad(out var m, out var stubBase, out var originalA, out var originalB)) return;
            if (m != moduleBase) return;

            bool wasOurs = false;
            var curA = new byte[HookStub.PatchLength];
            if (originalA != null && ReadAt(hProcess, targetA, curA) && IsOurPatch(curA, stubBase))
                wasOurs = true;
            var curB = new byte[HookStub.SuccessPatchLength];
            bool bOurs = originalB != null && ReadAt(hProcess, targetB, curB) && ArraysEqual(curB, HookStub.SuccessPatch);
            if (!wasOurs && !bOurs) return;

            if (wasOurs && originalA != null)
                ProtectWriteVerify(hProcess, targetA, originalA);
            if (bOurs && originalB != null)
                ProtectWriteVerify(hProcess, targetB, originalB);
            Win32Api.VirtualFreeEx(hProcess, new IntPtr(stubBase), IntPtr.Zero, 0x8000 /*MEM_RELEASE*/);
        }

        // ---------------- 还原 ----------------
        public static string Remove(IntPtr hProcess, long moduleBaseNow)
        {
            if (!PatchState.TryLoad(out var moduleBase, out var stubBase, out var originalA, out var originalB))
                return "未找到本模块的注入状态文件，无法还原（可能从未注入或文件被删）。";

            if (moduleBase != moduleBaseNow)
                return "模块基址与注入时不符（游戏已重启？），拒绝还原以免破坏进程。";

            long targetA = moduleBase + HookStub.HookRva;
            long targetB = moduleBase + HookStub.SuccessRva;

            // Hook A：必须是本模块的 detour 才还原
            if (originalA != null)
            {
                var curA = new byte[HookStub.PatchLength];
                if (!ReadAt(hProcess, targetA, curA)) return "读取 Hook 点 A 失败。";
                if (!IsOurPatch(curA, stubBase))
                    return "Hook 点 A 当前内容不是本模块的 patch，跳过还原（可能已被其他工具修改）。";
                if (!ProtectWriteVerify(hProcess, targetA, originalA))
                    return "还原 Hook A 失败或校验不一致。";
            }

            // Hook B：当前必须是我们的 NOP 才还原
            if (originalB != null)
            {
                var curB = new byte[HookStub.SuccessPatchLength];
                if (!ReadAt(hProcess, targetB, curB)) return "读取 Hook 点 B 失败。";
                if (!ArraysEqual(curB, HookStub.SuccessPatch))
                    return "Hook 点 B 当前内容不是本模块的 patch，跳过还原（可能已被其他工具修改）。";
                if (!ProtectWriteVerify(hProcess, targetB, originalB))
                    return "还原 Hook B 失败或校验不一致。";
            }

            Win32Api.VirtualFreeEx(hProcess, new IntPtr(stubBase), IntPtr.Zero, 0x8000 /*MEM_RELEASE*/);
            return "已还原两个 Hook 点的原始代码并释放 stub 内存。";
        }

        // ---------------- 状态读取 / F8 切换 ----------------
        /// <summary>读取游戏内 gEnabled 开关，返回 1=开启 0=关闭，-1=未注入。</summary>
        public static int ReadEnabledState(IntPtr hProcess)
        {
            if (!PatchState.TryLoad(out _, out var stubBase, out _, out _)) return -1;
            var buf = new byte[1];
            if (!ReadAt(hProcess, stubBase + HookStub.FlagEnabledOffset, buf)) return -1;
            return buf[0];
        }

        /// <summary>加载器侧 F8 切换：读 gEnabled → 翻转 → 写回。返回新状态（1/0），失败返回 -1。</summary>
        public static int ToggleEnabled(IntPtr hProcess)
        {
            if (!PatchState.TryLoad(out _, out var stubBase, out _, out _)) return -1;
            long addr = stubBase + HookStub.FlagEnabledOffset;
            var buf = new byte[1];
            if (!ReadAt(hProcess, addr, buf)) return -1;
            buf[0] = (byte)(buf[0] == 0 ? 1 : 0); // 翻转
            if (!WriteAt(hProcess, addr, buf)) return -1;
            return buf[0];
        }

        /// <summary>健康检查：两个 Hook 点是否仍在位、开关状态与自动判定累计次数。</summary>
        public static string Verify(IntPtr hProcess, long moduleBase)
        {
            if (!PatchState.TryLoad(out var m, out var stubBase, out _, out _))
                return "状态文件缺失：尚未注入过本模块。";
            if (m != moduleBase)
                return "模块基址与注入时不符：游戏可能已重启，需重新注入。";

            long targetA = moduleBase + HookStub.HookRva;
            long targetB = moduleBase + HookStub.SuccessRva;
            var curA = new byte[HookStub.PatchLength];
            if (!ReadAt(hProcess, targetA, curA)) return "读取 Hook 点 A 失败。";
            if (!IsOurPatch(curA, stubBase))
                return "Hook 点 A 字节与记录不符：patch 已被覆盖（需重新注入）。";
            var curB = new byte[HookStub.SuccessPatchLength];
            if (!ReadAt(hProcess, targetB, curB)) return "读取 Hook 点 B 失败。";
            if (!ArraysEqual(curB, HookStub.SuccessPatch))
                return "Hook 点 B 字节与记录不符：patch 已被覆盖（需重新注入）。";

            var st = new byte[5];
            if (!ReadAt(hProcess, stubBase + HookStub.FlagEnabledOffset, st)) return "读取 stub 状态失败。";
            int hits = BitConverter.ToInt32(st, 1);
            return $"Hook A/B 均在位。开关={st[0]}（1=开），自动判定累计触发 {hits} 次。";
        }

        /// <summary>供监控模式读取实时开关与命中计数；模块基址与记录不符（游戏重启）时返回 null。</summary>
        public static (int enabled, int hits)? ReadLiveState(IntPtr hProcess, long moduleBase)
        {
            if (!PatchState.TryLoad(out var m, out var stubBase, out _, out _)) return null;
            if (m != moduleBase) return null;
            var st = new byte[5];
            if (!ReadAt(hProcess, stubBase + HookStub.FlagEnabledOffset, st)) return null;
            return (st[0], BitConverter.ToInt32(st, 1));
        }

        // ---------------- 内部工具 ----------------
        /// <summary>校验"入口 detour"15 字节是否为指向 stubBase 的 jmp。</summary>
        private static bool IsOurPatch(byte[] current, long stubBase)
        {
            if (current.Length != HookStub.PatchLength) return false;
            for (int i = 0; i < Signature.Length; i++)
                if (current[i] != Signature[i]) return false;
            for (int i = 0; i < 8; i++)
                if (current[6 + i] != (byte)((ulong)stubBase >> (8 * i))) return false;
            return true;
        }

        private static bool ReadAt(IntPtr h, long addr, byte[] buf)
        {
            return Win32Api.ReadProcessMemory(h, new IntPtr(addr), buf, buf.Length, out _);
        }

        private static bool WriteAt(IntPtr h, long addr, byte[] buf)
        {
            return Win32Api.WriteProcessMemory(h, new IntPtr(addr), buf, buf.Length, out _);
        }

        /// <summary>临时改页属性→写入→恢复→刷新指令缓存，并回读校验。</summary>
        private static bool ProtectWriteVerify(IntPtr h, long addr, byte[] buf)
        {
            bool ok = Win32Api.VirtualProtectEx(h, new IntPtr(addr), new IntPtr(buf.Length),
                Win32Api.PAGE_EXECUTE_READWRITE, out uint oldProtect);
            if (!ok) return false;
            ok = WriteAt(h, addr, buf);
            ok &= Win32Api.FlushInstructionCache(h, new IntPtr(addr), new IntPtr(buf.Length));
            Win32Api.VirtualProtectEx(h, new IntPtr(addr), new IntPtr(buf.Length), oldProtect, out _);
            if (!ok) return false;

            var verify = new byte[buf.Length];
            return ReadAt(h, addr, verify) && ArraysEqual(verify, buf);
        }

        private static bool ArraysEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        /// <summary>仅供调试：以假地址生成 stub 并输出字节（--dump-stub 用）。</summary>
        public static byte[] DumpStubBytes()
        {
            long baseAddr = 0x140100000L;   // 假基址
            long target = 0x140000000L + HookStub.HookRva;
            return HookStub.Build(baseAddr, target);
        }
    }
}