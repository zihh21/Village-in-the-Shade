using System;

namespace FishingAutoCatch
{
    /// <summary>
    /// 注入器：向目标进程分配内存写入 stub，并打四个 16 进制 patch：
    ///   Hook 点 A：0x38A860（CTask_Menu_Fishing::update 入口，15 字节）
    ///     覆盖字节（HookStub.PatchLength=15）：mov rax,rsp / mov[rax+10],rbx / mov[rax+18],rsi / mov[rax+20],rdi，
    ///     替换为 `FF 25 00000000 <stub基址8字节> 90`（jmp qword[rip+0] → stub）。
    ///     stub 末尾复放这 15 字节并跳回 target+15（0x...A86F push rbp 处）继续原函数执行。
    ///   Hook 点 B：0x38B2FD（成功检查 je 0x38B484，6 字节）
    ///     `0F 84 81 01 00 00` → 6×NOP。0x38B2F6 调用 0x7491b0（时间轴播完判定）返回 0 时会
    ///     跳到 0x38B484 退出本帧，导致"伪造音符全命中仍卡在小游戏"；NOP 后音符达标即无条件走成功动作。
    ///   Hook 点 C：0x216C9C（state5 收竿动画完成续竿点，26 字节，resume 0x216CB6）
    ///     自动模式下改写 [r14+0x1DC]=0 回 state0 重新甩竿（含超时重甩）；否则写 1 走原版。
    ///   Hook 点 D：0x216B46（state4 入包调用点，45 字节，resume 0x216B73）
    ///     stub 复放 call 0x138BC0 后按返回值 al 更新 gBagFull / gFishCount（背包满检测 + 已钓计数）。
    ///
    /// 状态字节（stub 缓冲区尾部，由注入器写入）：gEnabled(1B) + gHits(4B) + gBagFull(1B) + gFishCount(4B)。
    /// </summary>
    internal static class Injector
    {
        /// <summary>detour 头部：jmp qword[rip+0]（6 字节）＋8 字节绝对地址。</summary>
        private static readonly byte[] Signature = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };

        // ---------------- 安装 ----------------
        public static string Install(IntPtr hProcess, long moduleBase)
        {
            long targetA = moduleBase + HookStub.HookRva;
            long targetB = moduleBase + HookStub.SuccessRva;
            long targetC = moduleBase + HookStub.CastRva;
            long targetD = moduleBase + HookStub.BagRva;

            // 0) 防重复注入：若是本工具上次打的补丁，先还原为原始字节再重打
            RestoreIfDoubleInject(hProcess, moduleBase, targetA, targetB, targetC, targetD);

            // 1) 读取四处被覆盖前的原始字节（用于状态文件/还原）
            var originalA = new byte[HookStub.PatchLength];
            if (!ReadAt(hProcess, targetA, originalA))
                return "读取 Hook 点 A 原始字节失败（句柄权限不足？）。";
            var originalB = new byte[HookStub.SuccessPatchLength];
            if (!ReadAt(hProcess, targetB, originalB))
                return "读取 Hook 点 B 原始字节失败（句柄权限不足？）。";
            var originalC = new byte[HookStub.CastPatchLength];
            if (!ReadAt(hProcess, targetC, originalC))
                return "读取 Hook 点 C 原始字节失败（句柄权限不足？）。";
            var originalD = new byte[HookStub.BagPatchLength];
            if (!ReadAt(hProcess, targetD, originalD))
                return "读取 Hook 点 D 原始字节失败（句柄权限不足？）。";

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
            // gEnabled=1(默认开启), gHits=0, gBagFull=0, gFishCount=0, gEntryA/C/D=0
            byte[] flags = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00 };
            if (!WriteAt(hProcess, stubBase + HookStub.FlagEnabledOffset, flags))
                return "写入状态字节失败。";

            // 4) 四个 Hook 点 detour / NOP
            //    Hook A → stub 区开头（Hook A 区偏移 0）；Hook C → stubBase+CastStubOffset（续竿区）；
            //    Hook D → stubBase+BagStubOffset（入包区）。若 C/D 也指向 stubBase 会跳进 Hook A stub，
            //    在 state5/state4 上下文中乱读 rcx 并 trampoline 到节奏判定内部，破坏整个钓鱼状态机（v1.0.0 缺陷）。
            if (!ProtectWriteVerify(hProcess, targetA, BuildDetourPatch(stubBase, HookStub.PatchLength)))
                return "写入 detour（Hook A）失败或校验不一致。";
            if (!ProtectWriteVerify(hProcess, targetB, HookStub.SuccessPatch))
                return "写入成功检查补丁（Hook B）失败或校验不一致。";
            if (!ProtectWriteVerify(hProcess, targetC,
                    BuildDetourPatch(stubBase + HookStub.CastStubOffset, HookStub.CastPatchLength)))
                return "写入 detour（Hook C）失败或校验不一致。";
            if (!ProtectWriteVerify(hProcess, targetD,
                    BuildDetourPatch(stubBase + HookStub.BagStubOffset, HookStub.BagPatchLength)))
                return "写入 detour（Hook D）失败或校验不一致。";

            // 5) 记录状态并返回
            PatchState.Save(moduleBase, stubBase, originalA, originalB, originalC, originalD);
            return $"注入成功。\n" +
                   $"  Hook A    : 0x{targetA:X}（入口 detour）\n" +
                   $"  Hook B    : 0x{targetB:X}（成功检查跳过）\n" +
                   $"  Hook C    : 0x{targetC:X}（续竿/自动重甩）\n" +
                   $"  Hook D    : 0x{targetD:X}（入包/背包满检测）\n" +
                   $"  Stub 基址 : 0x{stubBase:X}\n" +
                   $"  默认开关  : 开启（加载器按 F8 切换，开启 880Hz/关闭 440Hz 提示音）";
        }

        /// <summary>
        /// 若四个 Hook 点当前正是本模块上次写入的内容，则先还原原始字节并释放旧 stub，再让 Install 重打。
        /// v1.0.0 曾把 Hook C/D 的 detour 误指向 stubBase（Hook A 区），此处同时识别新（+CastStubOffset/+BagStubOffset）
        /// 与旧（指向 stubBase）两种形态，保证旧补丁也能被还原。
        /// </summary>
        private static void RestoreIfDoubleInject(IntPtr hProcess, long moduleBase,
            long targetA, long targetB, long targetC, long targetD)
        {
            if (!PatchState.TryLoad(out var m, out var stubBase,
                    out var originalA, out var originalB, out var originalC, out var originalD)) return;
            if (m != moduleBase) return;

            bool wasOurs = false;
            var curA = new byte[HookStub.PatchLength];
            if (originalA != null && ReadAt(hProcess, targetA, curA) && IsOurPatch(curA, stubBase))
                wasOurs = true;
            var curB = new byte[HookStub.SuccessPatchLength];
            bool bOurs = originalB != null && ReadAt(hProcess, targetB, curB) && ArraysEqual(curB, HookStub.SuccessPatch);
            var curC = new byte[HookStub.CastPatchLength];
            bool cOurs = originalC != null && ReadAt(hProcess, targetC, curC)
                         && IsOurPatchAny(curC, stubBase, stubBase + HookStub.CastStubOffset);
            var curD = new byte[HookStub.BagPatchLength];
            bool dOurs = originalD != null && ReadAt(hProcess, targetD, curD)
                         && IsOurPatchAny(curD, stubBase, stubBase + HookStub.BagStubOffset);
            if (!wasOurs && !bOurs && !cOurs && !dOurs) return;

            if (wasOurs && originalA != null) ProtectWriteVerify(hProcess, targetA, originalA);
            if (bOurs && originalB != null) ProtectWriteVerify(hProcess, targetB, originalB);
            if (cOurs && originalC != null) ProtectWriteVerify(hProcess, targetC, originalC);
            if (dOurs && originalD != null) ProtectWriteVerify(hProcess, targetD, originalD);
            Win32Api.VirtualFreeEx(hProcess, new IntPtr(stubBase), IntPtr.Zero, 0x8000 /*MEM_RELEASE*/);
        }

        // ---------------- 还原 ----------------
        public static string Remove(IntPtr hProcess, long moduleBaseNow)
        {
            if (!PatchState.TryLoad(out var moduleBase, out var stubBase,
                    out var originalA, out var originalB, out var originalC, out var originalD))
                return "未找到本模块的注入状态文件，无法还原（可能从未注入或文件被删）。";

            if (moduleBase != moduleBaseNow)
                return "模块基址与注入时不符（游戏已重启？），拒绝还原以免破坏进程。";

            long targetA = moduleBase + HookStub.HookRva;
            long targetB = moduleBase + HookStub.SuccessRva;
            long targetC = moduleBase + HookStub.CastRva;
            long targetD = moduleBase + HookStub.BagRva;

            // Hook A/C/D：必须是本模块的 detour 才还原
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

            if (originalC != null)
            {
                var curC = new byte[HookStub.CastPatchLength];
                if (!ReadAt(hProcess, targetC, curC)) return "读取 Hook 点 C 失败。";
                // 兼容 v1.0.0 旧误指 stubBase 的 patch 与新（+CastStubOffset）形态
                if (!IsOurPatchAny(curC, stubBase, stubBase + HookStub.CastStubOffset))
                    return "Hook 点 C 当前内容不是本模块的 patch，跳过还原（可能已被其他工具修改）。";
                if (!ProtectWriteVerify(hProcess, targetC, originalC))
                    return "还原 Hook C 失败或校验不一致。";
            }

            if (originalD != null)
            {
                var curD = new byte[HookStub.BagPatchLength];
                if (!ReadAt(hProcess, targetD, curD)) return "读取 Hook 点 D 失败。";
                if (!IsOurPatchAny(curD, stubBase, stubBase + HookStub.BagStubOffset))
                    return "Hook 点 D 当前内容不是本模块的 patch，跳过还原（可能已被其他工具修改）。";
                if (!ProtectWriteVerify(hProcess, targetD, originalD))
                    return "还原 Hook D 失败或校验不一致。";
            }

            Win32Api.VirtualFreeEx(hProcess, new IntPtr(stubBase), IntPtr.Zero, 0x8000 /*MEM_RELEASE*/);
            return "已还原四个 Hook 点的原始代码并释放 stub 内存。";
        }

        // ---------------- 状态读取 / F8 切换 ----------------
        /// <summary>读取游戏内 gEnabled 开关，返回 1=开启 0=关闭，-1=未注入。</summary>
        public static int ReadEnabledState(IntPtr hProcess)
        {
            if (!PatchState.TryLoad(out _, out var stubBase, out _, out _, out _, out _)) return -1;
            var buf = new byte[1];
            if (!ReadAt(hProcess, stubBase + HookStub.FlagEnabledOffset, buf)) return -1;
            return buf[0];
        }

        /// <summary>加载器侧 F8 切换：读 gEnabled → 翻转 → 写回。返回新状态（1/0），失败返回 -1。</summary>
        public static int ToggleEnabled(IntPtr hProcess)
        {
            if (!PatchState.TryLoad(out _, out var stubBase, out _, out _, out _, out _)) return -1;
            long addr = stubBase + HookStub.FlagEnabledOffset;
            var buf = new byte[1];
            if (!ReadAt(hProcess, addr, buf)) return -1;
            buf[0] = (byte)(buf[0] == 0 ? 1 : 0); // 翻转
            if (!WriteAt(hProcess, addr, buf)) return -1;
            return buf[0];
        }

        /// <summary>健康检查：四个 Hook 点是否在位（含 C/D 指向正确 stub 区）、Hook B 与开关状态是否一致、开关状态与两条计数。</summary>
        public static string Verify(IntPtr hProcess, long moduleBase)
        {
            if (!PatchState.TryLoad(out var m, out var stubBase, out _, out var originalB, out _, out _))
                return "状态文件缺失：尚未注入过本模块。";
            if (m != moduleBase)
                return "模块基址与注入时不符：游戏可能已重启，需重新注入。";

            long targetA = moduleBase + HookStub.HookRva;
            var curA = new byte[HookStub.PatchLength];
            if (!ReadAt(hProcess, targetA, curA)) return "读取 Hook 点 A 失败。";
            if (!IsOurPatch(curA, stubBase))
                return "Hook 点 A 字节与记录不符：patch 已被覆盖（需重新注入）。";

            // Hook C/D 的 detour 必须指向各自 stub 区（v1.0.0 曾误指向 stubBase 导致状态机错乱）
            long targetC = moduleBase + HookStub.CastRva;
            var curC = new byte[HookStub.CastPatchLength];
            if (!ReadAt(hProcess, targetC, curC)) return "读取 Hook 点 C 失败。";
            if (!IsOurPatch(curC, stubBase + HookStub.CastStubOffset))
                return "Hook 点 C detour 未指向续竿 stub 区（可能仍是 v1.0.0 错误补丁），需重新注入。";
            long targetD = moduleBase + HookStub.BagRva;
            var curD = new byte[HookStub.BagPatchLength];
            if (!ReadAt(hProcess, targetD, curD)) return "读取 Hook 点 D 失败。";
            if (!IsOurPatch(curD, stubBase + HookStub.BagStubOffset))
                return "Hook 点 D detour 未指向入包 stub 区（可能仍是 v1.0.0 错误补丁），需重新注入。";

            var st = new byte[22];
            if (!ReadAt(hProcess, stubBase + HookStub.FlagEnabledOffset, st)) return "读取 stub 状态失败。";
            int enabled = st[0];
            int hits = BitConverter.ToInt32(st, 1);
            int bagFull = st[5];
            int fishCount = BitConverter.ToInt32(st, 6);
            int entryA = BitConverter.ToInt32(st, 10);
            int entryC = BitConverter.ToInt32(st, 14);
            int entryD = BitConverter.ToInt32(st, 18);

            // Hook B 必须与 gEnabled 一致：开启→NOP（跳过成功检查），关闭→原始 je（等待时间线播完）
            var curB = new byte[HookStub.SuccessPatchLength];
            if (!ReadAt(hProcess, moduleBase + HookStub.SuccessRva, curB)) return "读取 Hook 点 B 失败。";
            bool bWantNop = enabled == 1;
            bool bMatch = bWantNop ? ArraysEqual(curB, HookStub.SuccessPatch)
                                   : originalB != null && ArraysEqual(curB, originalB);
            if (!bMatch)
                return $"Hook B 与开关状态不一致（当前开关={enabled}）。请用监控窗口按 F8 同步或重新注入。";

            return $"Hook A/B/C/D 均在位且与开关一致。开关={enabled}（1=开），" +
                   $"自动判定累计触发 {hits} 次，本次已钓 {fishCount} 条，背包满={bagFull}，" +
                   $"入口计数 A={entryA} C={entryC} D={entryD}（>0 表示游戏确实执行到对应 Hook 点）。";
        }

        /// <summary>
        /// 动态同步 Hook 点 B 字节：开启→写入 NOP（跳过 0x7491b0 成功检查）；
        /// 关闭→还原原始 `0F 84 81 01 00 00`（恢复"等待时间线播完再判定"的原版行为）。
        /// 返回结果描述字符串；失败返回以"失败"结尾的说明。
        /// </summary>
        public static string SyncHookB(IntPtr hProcess, long moduleBase, bool enabled)
        {
            if (!PatchState.TryLoad(out var m, out _, out _, out var originalB, out _, out _))
                return "状态文件缺失：尚未注入，无需同步。";
            if (m != moduleBase)
                return "模块基址与注入时不符（游戏可能已重启），拒绝修改 Hook B。";
            if (originalB == null || originalB.Length != HookStub.SuccessPatchLength)
                return "缺少 Hook B 原始字节记录（旧版本状态文件），请重新注入后再切换开关。";

            long targetB = moduleBase + HookStub.SuccessRva;
            byte[] want = enabled ? HookStub.SuccessPatch : originalB;
            var cur = new byte[HookStub.SuccessPatchLength];
            if (ReadAt(hProcess, targetB, cur) && ArraysEqual(cur, want))
                return enabled ? "Hook B 已处于跳过状态（开启）" : "Hook B 已是原版状态（关闭）";
            if (!ProtectWriteVerify(hProcess, targetB, want))
                return "Hook B 写入失败";
            Win32Api.FlushInstructionCache(hProcess, new IntPtr(targetB), new IntPtr(HookStub.SuccessPatchLength));
            return enabled ? "Hook B → NOP（跳过成功检查，自动判定生效）"
                           : "Hook B → 原版 je（恢复等待时间线播完，手动玩法生效）";
        }

        /// <summary>供监控模式读取实时开关与计数（含 v1.0.2 入口计数）；模块基址与记录不符（游戏重启）时返回 null。</summary>
        public static (int enabled, int hits, int bagFull, int fishCount,
                       int entryA, int entryC, int entryD)? ReadLiveState(IntPtr hProcess, long moduleBase)
        {
            if (!PatchState.TryLoad(out var m, out var stubBase, out _, out _, out _, out _)) return null;
            if (m != moduleBase) return null;
            var st = new byte[22];
            if (!ReadAt(hProcess, stubBase + HookStub.FlagEnabledOffset, st)) return null;
            return (st[0], BitConverter.ToInt32(st, 1), st[5], BitConverter.ToInt32(st, 6),
                    BitConverter.ToInt32(st, 10), BitConverter.ToInt32(st, 14), BitConverter.ToInt32(st, 18));
        }

        /// <summary>读取四个 Hook 点当前字节（十六进制），用于注入/自检的关键字节比对日志。</summary>
        public static string DumpHookBytes(IntPtr hProcess, long moduleBase)
        {
            long targetA = moduleBase + HookStub.HookRva;
            long targetB = moduleBase + HookStub.SuccessRva;
            long targetC = moduleBase + HookStub.CastRva;
            long targetD = moduleBase + HookStub.BagRva;

            var a = new byte[HookStub.PatchLength];
            if (!ReadAt(hProcess, targetA, a)) return "读取 Hook 点 A 失败。";
            var b = new byte[HookStub.SuccessPatchLength];
            if (!ReadAt(hProcess, targetB, b)) return "读取 Hook 点 B 失败。";
            var c = new byte[HookStub.CastPatchLength];
            if (!ReadAt(hProcess, targetC, c)) return "读取 Hook 点 C 失败。";
            var d = new byte[HookStub.BagPatchLength];
            if (!ReadAt(hProcess, targetD, d)) return "读取 Hook 点 D 失败。";

            return "A=" + Convert.ToHexString(a) + " | B=" + Convert.ToHexString(b) +
                   " | C=" + Convert.ToHexString(c) + " | D=" + Convert.ToHexString(d);
        }

        // ---------------- 内部工具 ----------------
        /// <summary>构造入口 detour：`FF 25 00000000 <stubBase 8字节>` + 剩余 NOP 填充到 patch 长度。</summary>
        private static byte[] BuildDetourPatch(long stubBase, int patchLen)
        {
            var patch = new byte[patchLen];
            Array.Copy(Signature, patch, Signature.Length);
            for (int i = 0; i < 8; i++) patch[6 + i] = (byte)((ulong)stubBase >> (8 * i));
            for (int i = 14; i < patchLen; i++) patch[i] = 0x90; // NOP 填充
            return patch;
        }

        /// <summary>校验"入口 detour"是否为指向 targetStubAddr 的 jmp（比较前 14 字节 + 地址）。</summary>
        private static bool IsOurPatch(byte[] current, long targetStubAddr)
        {
            if (current.Length < 14) return false;
            for (int i = 0; i < Signature.Length; i++)
                if (current[i] != Signature[i]) return false;
            for (int i = 0; i < 8; i++)
                if (current[6 + i] != (byte)((ulong)targetStubAddr >> (8 * i))) return false;
            return true;
        }

        /// <summary>detour 是否指向候选地址之一（用于兼容新/旧两种 stub 区指向）。</summary>
        private static bool IsOurPatchAny(byte[] current, params long[] candidates)
        {
            foreach (var c in candidates)
                if (IsOurPatch(current, c)) return true;
            return false;
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