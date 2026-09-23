using System;
using System.Diagnostics;
using System.Threading;

namespace FishingAutoCatch
{
    /// <summary>
    /// 监控模式（默认入口，双击直接使用，v1.0.0 自动钓鱼版）：
    ///   1. 若游戏未启动 → 持续等待（每秒探测一次），启动后自动注入四个 Hook（A 节奏判定 / B 成功检查 / C 续竿 / D 入包背包满）；
    ///   2. 注入后保持轮询：开关变化、自动判定触发次数、本次已钓条数、背包满状态实时打印；
    ///   3. 若游戏退出 → 自动等待其重新启动并再次自动注入（修复"重启游戏后 Mod 失效"问题）；
    ///   4. F8 切换在本进程内完成（GetAsyncKeyState 在任何进程都反映全局键盘状态，
    ///      因此任意时刻、非钓鱼场景也能切换），切换时加载器侧 Beep 提示；
    ///   5. 按任意键结束监控（已注入的 Hook 不受影响）。
    /// 窗口常驻，不会一闪而过。
    /// </summary>
    internal static class Monitor
    {
        /// <summary>VK_F8。</summary>
        private const int VK_F8 = 0x77;
        /// <summary>进程状态/注入轮询周期倍数（循环 100ms × 5 = 500ms）。</summary>
        private const int StateIntervalTicks = 5;

        public static void Run()
        {
            Console.WriteLine("FishingAutoCatch 监控模式已启动（v" + Program.Version + "）");
            Console.WriteLine("  等待游戏进程 village.exe……游戏启动后自动注入；");
            Console.WriteLine("  游戏重启后也会自动重新注入；按 F8 随时开关（任意场景有效，带提示音）；按任意键退出监控。");
            Console.WriteLine("  F8 开启自动钓鱼：水边甩竿后自动循环（等咬钩→自动判定→收杆入包→再甩竿）；");
            Console.WriteLine("  按游戏内收杆键（Enter/手柄 A）立即停止；背包满自动停下并提示。");
            Console.WriteLine();

            long lastPid = -1;
            bool injected = false;
            int lastEnabled = -1;
            int lastHits = -1;
            int lastFishCount = -1;
            int lastBagFull = -1;
            bool f8Down = false;
            int tick = 0;
            bool quit = false;

            while (!quit)
            {
                tick++;

                // 控制台按键：任意键退出监控，但 F8 除外——
                // 焦点在本窗口时按 F8 是切换开关，不应被当成退出键
                if (Console.KeyAvailable)
                {
                    var key = Console.ReadKey(true);
                    if (key.Key != ConsoleKey.F8) quit = true;
                }

                // ---- F8 全局热键（轻量轮询：按下沿才需要开进程句柄） ----
                bool down = (Win32Api.GetAsyncKeyState(VK_F8) & 0x8000) != 0;
                if (down && !f8Down)
                    HandleF8Toggle(ref injected, ref lastPid, ref lastEnabled);
                f8Down = down;

                // ---- 进程状态/注入轮询（约 500ms 一次） ----
                if (!quit && tick % StateIntervalTicks == 0)
                    PollState(ref injected, ref lastPid, ref lastEnabled, ref lastHits,
                              ref lastFishCount, ref lastBagFull);

                if (!quit) Thread.Sleep(100);
            }

            Console.WriteLine();
            Console.WriteLine("已退出监控模式。已注入的 Hook 仍生效（需重开本窗口才能按 F8 切换）。");
            Console.WriteLine("提示：游戏重启后重新运行本程序即可自动注入。");
        }

        /// <summary>处理 F8 按下沿：翻转 gEnabled + 同步 Hook B + 提示音 + 打印。</summary>
        private static void HandleF8Toggle(ref bool injected, ref long lastPid, ref int lastEnabled)
        {
            if (!injected || lastPid == -1)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 → 游戏未运行或尚未注入，切换无效。");
                return;
            }

            try
            {
                using (var p = ProcessManager.FindVillageProcess())
                {
                    if (p == null || p.Id != lastPid)
                    {
                        injected = false;
                        lastPid = -1;
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 → 游戏已退出，等待重新注入。");
                        return;
                    }

                    using (var handle = new SafeProcessHandle(p))
                    {
                        int newState = Injector.ToggleEnabled(handle.Handle);
                        if (newState < 0)
                        {
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 → 切换失败（状态不可读，可能游戏已重启），等待自动重注。");
                            return;
                        }
                        string txt = newState == 1 ? "已开启自动钓鱼（甩竿后自动循环）" : "已关闭自动钓鱼（完全原版）";
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 切换 → {txt}");
                        Log.Write("F8 切换 → " + txt);
                        Win32Api.Beep(newState == 1 ? 880u : 440u, 100); // 开启 880Hz / 关闭 440Hz，各 100ms
                        lastEnabled = newState;

                        // 关键：Hook B 必须随开关同步（关闭→还原原始 je，恢复原版"等待时间线播完"，
                        // 否则玩家打第一个音符就会因全音符检查立即判失败）
                        try
                        {
                            long moduleBase = ProcessManager.GetModuleBase(p);
                            string sync = Injector.SyncHookB(handle.Handle, moduleBase, newState == 1);
                            Console.WriteLine("  " + sync);
                            Log.Write(sync);
                        }
                        catch (Exception ex2)
                        {
                            Log.Write("同步 Hook B 异常: " + ex2.Message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Write("F8 切换异常", ex);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 切换异常，详见日志。");
            }
        }

        /// <summary>约 500ms 一次：等待/注入游戏，或轮询开关、命中次数、已钓条数与背包满状态。</summary>
        private static void PollState(ref bool injected, ref long lastPid, ref int lastEnabled,
            ref int lastHits, ref int lastFishCount, ref int lastBagFull)
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
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 游戏进程已退出，等待重新启动……（按任意键退出）");
                            injected = false;
                            lastPid = -1;
                            lastEnabled = -1;
                            lastHits = -1;
                            lastFishCount = -1;
                            lastBagFull = -1;
                        }
                        return;
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
                            string check = Injector.Verify(handle.Handle, moduleBase);
                            Console.WriteLine("  " + check);
                            injected = true;
                            lastPid = pid;
                            lastEnabled = -1;
                            lastHits = -1;
                            lastFishCount = -1;
                            lastBagFull = -1;
                        }
                        return;
                    }

                    // 已注入：轮询开关、命中计数、已钓条数与背包满状态
                    using (var handle = new SafeProcessHandle(p))
                    {
                        var state = Injector.ReadLiveState(handle.Handle, moduleBase);
                        if (state.HasValue)
                        {
                            if (lastEnabled != -1 && state.Value.enabled != lastEnabled)
                            {
                                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 开关 → " +
                                    (state.Value.enabled == 1 ? "已开启自动钓鱼" : "已关闭自动钓鱼（完全原版）"));
                                Log.Write("开关 → " +
                                    (state.Value.enabled == 1 ? "已开启自动钓鱼" : "已关闭自动钓鱼（完全原版）"));
                            }
                            if (state.Value.hits != lastHits && lastHits != -1 && state.Value.hits > 0)
                            {
                                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 自动判定已触发 {state.Value.hits} 次（钓鱼小游戏已自动完成）");
                                Log.Write($"自动判定已触发 {state.Value.hits} 次");
                            }
                            if (state.Value.fishCount != lastFishCount && lastFishCount != -1 && state.Value.fishCount > 0)
                            {
                                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 本次已自动钓获 {state.Value.fishCount} 条（已入包）");
                                Log.Write($"本次已自动钓获 {state.Value.fishCount} 条");
                            }
                            if (state.Value.bagFull != lastBagFull && lastBagFull != -1)
                            {
                                string msg = state.Value.bagFull == 1
                                    ? $"背包已满（第 {state.Value.fishCount} 条），自动停下。整理背包后自动恢复循环。"
                                    : "背包已恢复空间，自动循环继续。";
                                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {msg}");
                                Log.Write(msg);
                            }
                            lastEnabled = state.Value.enabled;
                            lastHits = state.Value.hits;
                            lastFishCount = state.Value.fishCount;
                            lastBagFull = state.Value.bagFull;

                            // Hook B 自愈：确保其字节与 gEnabled 一致（防 F8 切换丢失/二进制被外部覆盖）
                            try
                            {
                                string sync = Injector.SyncHookB(handle.Handle, moduleBase, state.Value.enabled == 1);
                                if (sync.StartsWith("Hook B →"))
                                {
                                    Console.WriteLine("  [自愈] " + sync);
                                    Log.Write("Hook B 自愈: " + sync);
                                }
                            }
                            catch (Exception ex)
                            {
                                Log.Write("Hook B 自愈异常: " + ex.Message);
                            }
                        }

                        // 每约 10 秒自检一次四个 Hook 点是否仍在位
                        if (lastEnabled == 1 && tickSelfCheck())
                        {
                            string check = Injector.Verify(handle.Handle, moduleBase);
                            if (!check.StartsWith("Hook A/B/C/D 均在位"))
                            {
                                Console.WriteLine("[监控] " + check);
                                Log.Write("自检: " + check);
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
        }

        private static int _selfTickCount;
        /// <summary>约每 10 秒（500ms × 20）返回一次 true。</summary>
        private static bool tickSelfCheck() => ++_selfTickCount % 20 == 0;
    }
}