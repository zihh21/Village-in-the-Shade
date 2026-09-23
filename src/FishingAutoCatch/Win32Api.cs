using System;
using System.Runtime.InteropServices;

namespace FishingAutoCatch
{
    /// <summary>注入所需的 Win32 API 封装。</summary>
    internal static class Win32Api
    {
        public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, IntPtr size,
            uint allocationType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr process, IntPtr address, IntPtr size, uint freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer,
            int size, out IntPtr written);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer,
            int size, out IntPtr read);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr process, IntPtr address, IntPtr size,
            uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr process, IntPtr address, IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetModuleHandleA(string moduleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        /// <summary>
        /// 解析 user32!GetAsyncKeyState 地址。
        /// 系统 DLL 在各进程中的加载基址一致，可直接在加载器侧解析后供 stub 使用。
        /// </summary>
        public static long GetAsyncKeyStateAddress()
        {
            IntPtr mod = GetModuleHandleA("user32.dll");
            if (mod == IntPtr.Zero) return 0;
            return GetProcAddress(mod, "GetAsyncKeyState").ToInt64();
        }

        /// <summary>解析 kernel32!Beep 地址（F8 切换提示音，stub 内调用）。</summary>
        public static long BeepAddress()
        {
            IntPtr mod = GetModuleHandleA("kernel32.dll");
            if (mod == IntPtr.Zero) return 0;
            return GetProcAddress(mod, "Beep").ToInt64();
        }
    }
}