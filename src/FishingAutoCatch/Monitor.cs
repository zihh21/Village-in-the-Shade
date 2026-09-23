using System;
using System.Collections.Generic;
using System.Threading;

namespace FishingAutoCatch
{
    /// <summary>
    /// 监控模式（默认入口，双击直接使用）：
    ///   1. 若游戏未启动 → 持续等待（每秒探测一次），启动后自动注入四个 Hook（A 节奏判定 / B 成功检查 / C 续竿 / D 入包背包满）；
    ///   2. 支持多个游戏实例（v1.0.3）：对每个 village.exe 进程独立注入与轮询——
    ///      游戏重启/双开时新实例也会自动注入，修复"重启游戏后 Mod 不生效"（v1.0.2 根因：
    ///      新启动的实例从未被注入 Hook，用户在其中的钓鱼流程完全原版）；
    ///   3. 注入后保持轮询：开关变化、自动判定触发次数、本次已钓条数、背包满状态、三口入口计数实时打印；
    ///   4. 若某实例退出 → 自动移除其跟踪，等它再次启动时重新注入；
    ///   5. F8 切换在本进程内完成（GetAsyncKeyState 在任何进程都反映全局键盘状态，
    ///      任意时刻、非钓鱼场景也能切换），对**所有已注入实例**统一生效并提示音；
    ///   6. 按任意键结束监控（已注入的 Hook 不受影响）。
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
            Console.WriteLine("  支持多游戏实例：每个 village.exe（含重启/双开的新进程）都会自动注入；");
            Console.WriteLine("  按 F8 对全部实例开关（任意场景有效，带提示音）；按任意键退出监控。");
            Console.WriteLine("  F8 开启自动钓鱼：水边甩竿后自动循环（等咬钩→自动判定→收杆入包→再甩竿）；");
            Console.WriteLine("  按游戏内收杆键（Enter/手柄 A）立即停止；背包满自动停下并提示。");
            Console.WriteLine();

            // 实例跟踪表：key = 游戏进程 PID（moduleBase 因 ASLR 关闭可能多个实例相同，必须用 PID 区分）
            var instances = new Dictionary<long, InstanceState>();
            bool quit = false;
            bool f8Down = false;
            int tick = 0;

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
                    InstanceMonitor.FlipAll(instances);
                f8Down = down;

                // ---- 多实例注入/轮询（约 500ms 一次） ----
                if (!quit && tick % StateIntervalTicks == 0)
                {
                    try
                    {
                        InstanceMonitor.PollAll(instances);
                    }
                    catch (Exception ex)
                    {
                        Log.Write("监控轮询异常: " + ex.Message);
                    }
                }

                if (!quit) Thread.Sleep(100);
            }

            Console.WriteLine();
            Console.WriteLine("已退出监控模式。已注入的 Hook 仍生效（需重开本窗口才能按 F8 切换）。");
            Console.WriteLine("提示：游戏重启后重新运行本程序即可自动注入。");
        }
    }
}