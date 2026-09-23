using System;
using System.Diagnostics;
using System.Threading;

namespace FishingAutoCatch
{
    /// <summary>
    /// 监控模式（默认入口，双击直接使用）：
    ///   1. 若游戏未启动 → 持续等待（每秒探测一次），启动后自动注入；
    ///   2. 注入后保持轮询：F8 开关变化、自动判定触发次数实时打印；
    ///   3. 若游戏退出 → 自动等待其重新启动并再次自动注入（修复"重启游戏后 Mod 失效"问题）；
    ///   4. 按任意键结束监控（已注入的 Hook 不受影响，游戏内 F8 仍可开关）。
    /// 窗口常驻，不会一闪而过。
    /// </summary>
    internal static class Monitor
    {
        public static void Run()
        {
            Console.WriteLine("FishingAutoCatch 监控模式已启动（v" + Program.Version + "）");
            Console.WriteLine("  等待游戏进程 village.exe……游戏启动后自动注入；");
            Console.WriteLine("  游戏重启后也会自动重新注入；按任意键退出监控。");
            Console.WriteLine();

            long lastPid = -1;
            bool injected = false;
            int lastEnabled = -1;
            int lastHits = -1;
            int lastSelfCheck = 0;

            while (!Console.KeyAvailable)
            {
                try
                {
                    using (var p = ProcessManager.FindVillageProcess())
                    {
                        if (p == null)
                        {
                            if (injected)
                            {
                                Log.Write("游戏进程已退出，等待重新启动……");
                                Console.WriteLine("[监控] 游戏进程已退出，等待重新启动……（按任意键退出）");
                                injected = false;
                                lastPid = -1;
                                lastEnabled = -1;
                                lastHits = -1;
                            }
                            Thread.Sleep(1000);
                            continue;
                        }

                        long pid = p.Id;
                        long moduleBase = ProcessManager.GetModuleBase(p);

                        if (!injected || pid != lastPid)
                        {
                            // 首次发现或进程重启：注入 + 校验
                            using (var handle = new SafeProcessHandle(p))
                            {
                                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 检测到游戏进程 PID={pid}，注入中……");
                                string result = Injector.Install(handle.Handle, moduleBase);
                                Console.WriteLine("  " + result.Replace("\n", "\n  "));
                                Log.Write($"注入 PID={pid}: " + result.Replace("\n", " | "));
                                injected = true;
                                lastPid = pid;
                                lastEnabled = -1;
                                lastHits = -1;
                            }
                        }
                        else
                        {
                            // 已注入：轮询开关与命中计数
                            using (var handle = new SafeProcessHandle(p))
                            {
                                var state = Injector.ReadLiveState(handle.Handle, moduleBase);
                                if (state.HasValue)
                                {
                                    if (lastEnabled != -1 && state.Value.enabled != lastEnabled)
                                    {
                                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 切换 → " +
                                            (state.Value.enabled == 1 ? "已开启自动判定" : "已关闭自动判定"));
                                        Log.Write("F8 切换 → " +
                                            (state.Value.enabled == 1 ? "已开启自动判定" : "已关闭自动判定"));
                                    }
                                    if (state.Value.hits != lastHits && lastHits != -1 && state.Value.hits > 0)
                                    {
                                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 自动判定已触发 {state.Value.hits} 次（钓鱼小游戏已自动完成）");
                                        Log.Write($"自动判定已触发 {state.Value.hits} 次");
                                    }
                                    lastEnabled = state.Value.enabled;
                                    lastHits = state.Value.hits;
                                }

                                // 每约 10 秒自检一次 Hook 点是否仍在位
                                if (lastSelfCheck++ % 20 == 0 && state.HasValue && state.Value.enabled == 1)
                                {
                                    string check = Injector.Verify(handle.Handle, moduleBase);
                                    if (!check.StartsWith("Hook 在位"))
                                    {
                                        Console.WriteLine("[监控] " + check);
                                        Log.Write("自检: " + check);
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    // 进程在探测途中退出等瞬态错误，忽略并继续轮询
                    Log.Write("监控轮询异常: " + ex.Message);
                    Thread.Sleep(800);
                }

                Thread.Sleep(500);
            }

            Console.WriteLine();
            Console.WriteLine("已退出监控模式。已注入的 Hook 仍生效（游戏内 F8 可开关）。");
            Console.WriteLine("提示：游戏重启后需重新运行本程序即可自动注入。");
        }
    }
}