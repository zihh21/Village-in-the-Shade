using System;
using System.IO;
using System.Text;

namespace FishingAutoCatch
{
    /// <summary>
    /// 钓鱼自动收杆（FishingAutoCatch）启动器 / 注入器。
    /// 用法：
    ///   FishingAutoCatch               注入（默认）
    ///   FishingAutoCatch --status     查询开关状态
    ///   FishingAutoCatch --remove     还原 Hook
    ///   FishingAutoCatch --dump-stub  输出 stub 机器码（调试/反汇编验证用）
    /// </summary>
    internal static class Program
    {
        /// <summary>与 version.txt 同步维护。</summary>
        public const string Version = "0.1.0";

        private static int Main(string[] args)
        {
            // 每格最多到 9 的版本规则见 version.txt
            Console.OutputEncoding = Encoding.UTF8;

            if (args.Length > 0 && (args[0] == "--help" || args[0] == "-h"))
            {
                PrintUsage();
                return 0;
            }

            if (args.Length > 0 && args[0] == "--dump-stub")
            {
                byte[] code = Injector.DumpStubBytes();
                string path = args.Length > 1 ? args[1] : Path.Combine(Path.GetTempPath(), "fishing_stub.bin");
                File.WriteAllBytes(path, code);
                Console.WriteLine($"stub 机器码已写出（{code.Length} 字节）：{path}");
                Console.WriteLine(BitConverter.ToString(code).Replace("-", " "));
                return 0;
            }

            using var process = ProcessManager.FindVillageProcess();
            if (process == null)
            {
                Console.WriteLine("未找到运行中的 village.exe。");
                Console.WriteLine("请先启动《Village in the Shade》并确认已进入游戏标题画面，再运行本程序注入。");
                return 1;
            }

            long moduleBase = ProcessManager.GetModuleBase(process);
            using (var handle = new SafeProcessHandle(process))
            {
                if (args.Length > 0 && args[0] == "--remove")
                {
                    Console.WriteLine(Injector.Remove(handle.Handle, moduleBase));
                    return 0;
                }

                if (args.Length > 0 && args[0] == "--status")
                {
                    int state = Injector.ReadEnabledState(handle.Handle);
                    Console.WriteLine(state == 1 ? "钓鱼自动收杆：开启（游戏中按 F8 切换）"
                            : state == 0 ? "钓鱼自动收杆：关闭（游戏中按 F8 切换）"
                            : "未注入或状态文件缺失。");
                    return 0;
                }

                Console.WriteLine("正在为目标进程注入钓鱼自动收杆 Hook……");
                Console.WriteLine("  进程     : village.exe (PID " + process.Id + ")");
                Console.WriteLine("  模块基址 : 0x" + moduleBase.ToString("X"));
                Console.WriteLine(Injector.Install(handle.Handle, moduleBase));
                Console.WriteLine("说明：本 Mod 只跳过「咬钩后拉线节奏小游戏」，甩竿→等咬钩→收杆流程不变；");
                Console.WriteLine("      鱼获按正规成功流程结算。按 F8 随时开启/关闭。");
            }
            return 0;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("钓鱼自动收杆 (FishingAutoCatch) v" + Version);
            Console.WriteLine("用法：");
            Console.WriteLine("  FishingAutoCatch           向运行中的游戏注入 Hook（默认开启，游戏内 F8 切换）");
            Console.WriteLine("  FishingAutoCatch --status  查询当前开关状态");
            Console.WriteLine("  FishingAutoCatch --remove  还原被 Hook 的原始代码");
            Console.WriteLine("  FishingAutoCatch --dump-stub [路径]  输出 stub 机器码用于反汇编验证");
        }
    }

    /// <summary>封装进程句柄的 IDisposable。</summary>
    internal sealed class SafeProcessHandle : IDisposable
    {
        public IntPtr Handle { get; }

        public SafeProcessHandle(System.Diagnostics.Process p)
        {
            Handle = Win32Api.OpenProcess(Win32Api.PROCESS_ALL_ACCESS, false, p.Id);
            if (Handle == IntPtr.Zero)
                throw new InvalidOperationException(
                    "OpenProcess 失败（错误码 " + System.Runtime.InteropServices.Marshal.GetLastWin32Error() +
                    "）。请以管理员身份运行或确认与游戏同一用户。");
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero) Win32Api.CloseHandle(Handle);
        }
    }
}