using System;
using System.Text;

namespace FishingAutoCatch
{
    /// <summary>
    /// 注入器：向目标进程分配内存写入 stub，并在 0x38A860 打 15 字节 inline hook。
    /// 覆盖字节（HookStub.PatchLength=15）：mov rax,rsp / mov[rax+10],rbx / mov[rax+18],rsi / mov[rax+20],rdi，
    /// 替换为 `FF 25 00000000 <stub基址8字节> 90`（jmp qword[rip+0] → stub）。
    /// stub 末尾复放这 15 字节并跳回 target+15（0x...A86F push rbp 处）继续原函数执行。
    /// </summary>
    internal static class Injector
    {
        /// <summary>patch 头部：jmp [rip+0]（6 字节）＋8 字节绝对地址＋1 字节填充。</summary>
        private static readonly byte[] Signature = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };

        public static string Install(IntPtr hProcess, long moduleBase)
        {
            long target = moduleBase + HookStub.HookRva;
            long getAsyncKeyState = Win32Api.GetAsyncKeyStateAddress();
            if (getAsyncKeyState == 0)
                return "解析 user32!GetAsyncKeyState 失败，无法注入。";

            // 1) 读取被覆盖前的原始字节（用于状态文件/还原）
            var original = new byte[HookStub.PatchLength];
            if (!ReadAt(hProcess, target, original))
                return "读取 Hook 点原始字节失败（句柄权限不足？）。";

            // 2) 在目标进程分配可执行内存
            IntPtr stubBasePtr = Win32Api.VirtualAllocEx(hProcess, IntPtr.Zero,
                new IntPtr(HookStub.StubBufferSize), Win32Api.MEM_COMMIT | Win32Api.MEM_RESERVE,
                Win32Api.PAGE_EXECUTE_READWRITE);
            if (stubBasePtr == IntPtr.Zero)
                return "VirtualAllocEx 失败（错误码 " + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + "）。";
            long stubBase = stubBasePtr.ToInt64();

            // 3) 生成并写入 stub 代码（绝对地址按 stubBase 回填）
            byte[] code = HookStub.Build(stubBase, target, getAsyncKeyState);
            if (!WriteAt(hProcess, stubBase, code))
                return "写入 stub 代码失败。";
            byte[] flags = { 0x01, 0x00 }; // gEnabled=1（默认开启）, gLastF8=0
            if (!WriteAt(hProcess, stubBase + HookStub.FlagEnabledOffset, flags))
                return "写入状态字节失败。";

            // 4) 在 Hook 点写入 detour
            var patch = new byte[HookStub.PatchLength];
            Array.Copy(Signature, patch, Signature.Length);
            for (int i = 0; i < 8; i++) patch[6 + i] = (byte)((ulong)stubBase >> (8 * i));
            patch[14] = 0x90; // 填充（0x...A86E，原 prologue 末尾一字节）

            if (!ProtectWriteVerify(hProcess, target, patch))
                return "写入 detour 失败或校验不一致。";

            // 5) 记录状态并返回
            PatchState.Save(moduleBase, stubBase, original);
            return $"注入成功。\n" +
                   $"  Hook 点   : 0x{target:X}\n" +
                   $"  Stub 基址 : 0x{stubBase:X}\n" +
                   $"  默认开关  : 开启（游戏中按 F8 切换）";
        }

        /// <summary>还原 Hook（要求当前字节仍为本模块的 patch 签名，且模块基址一致）。</summary>
        public static string Remove(IntPtr hProcess, long moduleBaseNow)
        {
            if (!PatchState.TryLoad(out var moduleBase, out var stubBase, out var original))
                return "未找到本模块的注入状态文件，无法还原（可能从未注入或文件被删）。";

            if (moduleBase != moduleBaseNow)
                return "模块基址与注入时不符（游戏已重启？），拒绝还原以免破坏进程。";

            long target = moduleBase + HookStub.HookRva;
            var current = new byte[HookStub.PatchLength];
            if (!ReadAt(hProcess, target, current)) return "读取 Hook 点失败。";

            if (!IsOurPatch(current, stubBase))
                return "Hook 点当前内容不是本模块的 patch，跳过还原（可能已被其他工具修改）。";

            if (!ProtectWriteVerify(hProcess, target, original))
                return "还原原始字节失败或校验不一致。";

            Win32Api.VirtualFreeEx(hProcess, new IntPtr(stubBase), IntPtr.Zero, 0x8000 /*MEM_RELEASE*/);
            return "已还原原始代码并释放 stub 内存。";
        }

        /// <summary>读取游戏内 gEnabled 开关，返回 1=开启 0=关闭。</summary>
        public static int ReadEnabledState(IntPtr hProcess)
        {
            if (!PatchState.TryLoad(out var moduleBase, out var stubBase, out _)) return -1;
            var buf = new byte[1];
            if (!ReadAt(hProcess, stubBase + HookStub.FlagEnabledOffset, buf)) return -1;
            return buf[0];
        }

        /// <summary>校验当前 15 字节是否为指向 stubBase 的 detour。</summary>
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
            long gask = 0x7FF800000000L;    // 假 GetAsyncKeyState
            return HookStub.Build(baseAddr, target, gask);
        }
    }
}