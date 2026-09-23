using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace FishingAutoCatch
{
    /// <summary>
    /// 自动钓鱼（FishingAutoCatch）启动器 / 注入器。
    /// 用法：
    ///   FishingAutoCatch                 监控模式（默认）：等待/自动注入多个游戏实例、实时显示 F8 开关与自动循环状态、实例重启/双开自动重注
    ///   FishingAutoCatch --once          一次性注入（若游戏未启动则等待最多 30 秒，操作最新启动的实例）
    ///   FishingAutoCatch --status        查询开关状态
    ///   FishingAutoCatch --verify        健康检查（Hook 是否在位 + 触发计数）
    ///   FishingAutoCatch --remove        还原 Hook
    ///   FishingAutoCatch --dump-stub     输出 stub 机器码（调试/反汇编验证用）
    /// </summary>
    internal static class Program
    {
        /// <summary>与 version.txt 同步维护。</summary>
        public const string Version = "1.0.3";

        private static int Main(string[] args)
        {
            Console.Title = "FishingAutoCatch v" + Version;
            Console.OutputEncoding = Encoding.UTF8;
            int code = 0;
            try
            {
                code = Run(args);
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("发生未处理异常：");
                Console.WriteLine(ex);
                Log.Write("未处理异常", ex);
                code = 1;
            }
            finally
            {
                // 双击运行时窗口保持住，避免"一闪而过"被误认为闪退
                if (args == null || args.Length == 0 || IsKeepOpen(args))
                {
                    Console.WriteLine();
                    Console.WriteLine("按任意键退出……");
                    try { Console.ReadKey(true); } catch { }
                }
            }
            return code;
        }

        /// <summary>监控模式刚才已在按键上循环退出，无需再等键；其余模式等一个键再关窗口。</summary>
        private static bool IsKeepOpen(string[] args)
        {
            if (args.Length == 0) return false; // 监控模式：循环内已等待按键
            return args[0] != "--dump-stub";    // --dump-stub 供脚本调用，直接结束
        }

        private static int Run(string[] args)
        {
            Log.Write("启动 FishingAutoCatch v" + Version + "  args=" + string.Join(" ", args));

            if (args.Length > 0 && args[0] == "--help")
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

            // 默认：监控模式（自动等待游戏启动、对全部实例自动注入、实例重启/双开自动重注）
            if (args.Length == 0)
            {
                Monitor.Run();
                return 0;
            }

            // ---- 一次性/查询类模式：等待游戏进程（若未启动） ----
            using (var process = WaitForProcess(args[0] == "--once" ? 30 : 5))
            {
                if (process == null)
                {
                    Console.WriteLine("未找到运行中的 village.exe。");
                    Console.WriteLine("若游戏尚未启动，请直接不带参数运行本程序进入监控模式（会自动等待并注入）。");
                    return 1;
                }

                long moduleBase = ProcessManager.GetModuleBase(process);
                using (var handle = new SafeProcessHandle(process))
                {
                    switch (args[0])
                    {
                        case "--remove":
                            Console.WriteLine(Injector.Remove(handle.Handle, process.Id, moduleBase));
                            return 0;

                        case "--status":
                            int state = Injector.ReadEnabledState(handle.Handle, process.Id);
                            Console.WriteLine(state == 1 ? "自动钓鱼：开启（保持监控窗口运行，任意场景按 F8 切换，开启 880Hz/关闭 440Hz 提示音）"
                                    : state == 0 ? "自动钓鱼：关闭（保持监控窗口运行，任意场景按 F8 切换）"
                                    : "未注入或状态文件缺失。");
                            return 0;

                        case "--verify":
                            Console.WriteLine(Injector.Verify(handle.Handle, process.Id, moduleBase));
                            return 0;

                        case "--once":
                            Console.WriteLine("正在为目标进程注入自动钓鱼 Hook（四 Hook：节奏判定/成功检查/续竿/背包满）……");
                            Console.WriteLine("  进程     : village.exe (PID " + process.Id + ")");
                            Console.WriteLine("  模块基址 : 0x" + moduleBase.ToString("X"));
                            Console.WriteLine(Injector.Install(handle.Handle, process.Id, moduleBase));
                            Console.WriteLine(Injector.Verify(handle.Handle, process.Id, moduleBase));
                            Log.Write($"一次性注入完成 PID={process.Id}");
                            return 0;

                        default:
                            Console.WriteLine("未知参数：" + args[0]);
                            PrintUsage();
                            return 1;
                    }
                }
            }
        }

        /// <summary>按超时秒数轮询等待游戏进程；超时未找到返回 null。</summary>
        private static Process WaitForProcess(int timeoutSeconds)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.Elapsed.TotalSeconds < timeoutSeconds)
            {
                var p = ProcessManager.FindVillageProcess();
                if (p != null) return p;
                if (timeoutSeconds > 5) Console.WriteLine("  等待 village.exe 启动……(" + sw.Elapsed.TotalSeconds.ToString("0") + "s / " + timeoutSeconds + "s)");
                Thread.Sleep(1000);
            }
            return null;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("自动钓鱼 (FishingAutoCatch) v" + Version);
            Console.WriteLine("用于《Village in the Shade》：F8 开启后在水边甩竿即进入自动循环——");
            Console.WriteLine("等咬钩→自动判定成功→收杆入包→自动再甩竿；F8 关闭则完全原版。");
            Console.WriteLine("停止：按游戏内收杆键（Enter/手柄 A）立即走原版手动收杆路径；");
            Console.WriteLine("背包满自动停下并提示，清包后自动恢复循环；不修改鱼品质/数量。");
            Console.WriteLine();
            Console.WriteLine("用法（不带参数运行 = 监控模式，推荐）：");
            Console.WriteLine("  FishingAutoCatch             监控模式：等待游戏启动→对所有实例自动注入→实时显示 F8 开关/已钓条数/背包满→实例重启或双开也自动重注");
            Console.WriteLine("  FishingAutoCatch --once     一次性注入（等待游戏最多 30 秒，操作最新启动的实例）");
            Console.WriteLine("  FishingAutoCatch --status   查询当前开关状态");
            Console.WriteLine("  FishingAutoCatch --verify   健康检查（四个 Hook 是否在位、触发次数、已钓条数）");
            Console.WriteLine("  FishingAutoCatch --remove   还原被 Hook 的原始代码");
            Console.WriteLine("  FishingAutoCatch --dump-stub [路径]  输出 stub 机器码用于反汇编验证");
            Console.WriteLine();
            Console.WriteLine("全局热键：F8 开启/关闭（开启发出 880Hz 提示音，关闭发出 440Hz 提示音）；");
            Console.WriteLine("          由本程序监控窗口检测，任意界面/场景下均有效，需保持监控窗口运行。");
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