using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace FishingAutoCatch
{
    /// <summary>
    /// 单个游戏实例的注入跟踪状态（v1.0.3 多实例支持）。
    /// 由于游戏关闭 ASLR、多个实例的 moduleBase 相同，必须用 PID 区分实例。
    /// </summary>
    internal sealed class InstanceState
    {
        public long Pid;
        public long ModuleBase;
        public bool Injected;
        public int LastEnabled = -1, LastHits = -1, LastFishCount = -1, LastBagFull = -1;
        public int LastEntryA = -1, LastEntryC = -1, LastEntryD = -1, LastEntryE = -1;
        /// <summary>自检节拍（约每 10 秒 Verify 一次五个 Hook 是否仍在位）。</summary>
        public int SelfTick;
        /// <summary>上次自动重注入时刻（Environment.TickCount），防 Verify 失败死循环重注。</summary>
        public int LastReinjectAt;

        public void ResetLast()
        {
            LastEnabled = -1; LastHits = -1; LastFishCount = -1; LastBagFull = -1;
            LastEntryA = -1; LastEntryC = -1; LastEntryD = -1; LastEntryE = -1; SelfTick = 0;
        }
    }

    /// <summary>
    /// 多实例监控核心（v1.0.3）：
    ///   - PollAll：枚举全部 village.exe，新实例自动注入，已注入实例轮询实时状态，
    ///     已退出实例自动移除跟踪（等待其重启后再自动注入）；
    ///   - FlipAll：F8 按下沿对"所有已注入实例"统一翻转开关并同步 Hook B——无论用户在哪个实例游玩都生效。
    /// 解决 v1.0.2 的根因：旧版监控用 FindVillageProcess 只绑定最早发现的实例，
    /// 用户重启/双开游戏后新实例从未被注入，Mod 完全无效。
    /// </summary>
    internal static class InstanceMonitor
    {
        public static void PollAll(Dictionary<long, InstanceState> instances)
        {
            List<Process> procs;
            try { procs = ProcessManager.FindAllVillageProcesses(); }
            catch (Exception ex) { Log.Write("枚举游戏进程异常: " + ex.Message); return; }

            // 1) 移除已退出的实例（游戏重启时旧进程退出 → 清理跟踪，等待新进程）
            if (instances.Count > 0)
            {
                var alive = new HashSet<long>();
                foreach (var p in procs) alive.Add(p.Id);
                var dead = new List<long>();
                foreach (var pid in instances.Keys)
                    if (!alive.Contains(pid)) dead.Add(pid);
                foreach (var pid in dead)
                {
                    Log.Write($"游戏实例 PID={pid} 已退出，移除其跟踪。");
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 游戏实例 PID={pid} 已退出。");
                    instances.Remove(pid);
                }
            }

            // 2) 新实例注入 / 已注入实例轮询
            foreach (var p in procs)
            {
                using (p)
                {
                    long pid = p.Id;
                    long moduleBase;
                    try { moduleBase = ProcessManager.GetModuleBase(p); }
                    catch (Exception ex)
                    {
                        Log.Write($"PID={pid} 读取模块基址失败: {ex.Message}");
                        continue;
                    }

                    if (!instances.TryGetValue(pid, out var st))
                    {
                        st = new InstanceState { Pid = pid, ModuleBase = moduleBase };
                        instances[pid] = st;
                        InjectInstance(p, st);
                    }
                    else
                    {
                        st.ModuleBase = moduleBase;
                        PollInstance(p, st);
                    }
                }
            }
        }

        /// <summary>对某个新发现的游戏实例：注入 + 回读五个 Hook 点真实字节 + Verify 校验。</summary>
        private static void InjectInstance(Process p, InstanceState st)
        {
            using (var handle = new SafeProcessHandle(p))
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] 检测到游戏实例 PID={st.Pid}，注入中……");
                string result = Injector.Install(handle.Handle, st.Pid, st.ModuleBase);
                Console.WriteLine("  " + result.Replace("\n", "\n  "));
                Log.Write($"注入 PID={st.Pid}: " + result.Replace("\n", " | "));

                string hookBytes = Injector.DumpHookBytes(handle.Handle, st.ModuleBase);
                Console.WriteLine("  [注入回读] " + hookBytes);
                Log.Write($"注入回读 PID={st.Pid} " + hookBytes);

                string check = Injector.Verify(handle.Handle, st.Pid, st.ModuleBase);
                Console.WriteLine("  " + check);
                Log.Write($"注入后 Verify PID={st.Pid}: " + check);

                st.Injected = true;
                st.ResetLast();
            }
        }

        /// <summary>轮询某实例实时状态（开关/命中/已钓/背包满/四口入口计数）+ Hook B 自愈 + 十日 Verify。</summary>
        private static void PollInstance(Process p, InstanceState st)
        {
            using (var handle = new SafeProcessHandle(p))
            {
                var state = Injector.ReadLiveState(handle.Handle, st.Pid, st.ModuleBase);
                if (!state.HasValue)
                {
                    // gEnabled 读不到：状态文件缺失或模块基址不符（理论上不会发生，多实例各自有记录）
                    Log.Write($"PID={st.Pid} 状态读取失败，等待重新注入。");
                    st.Injected = false;
                    return;
                }

                var v = state.Value;
                if (st.LastEnabled != -1 && v.enabled != st.LastEnabled)
                {
                    string txt = v.enabled == 1 ? "已开启自动钓鱼" : "已关闭自动钓鱼（完全原版）";
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] PID={st.Pid} 开关 → {txt}");
                    Log.Write($"开关 PID={st.Pid} → {txt}");
                }
                if (v.hits != st.LastHits && st.LastHits != -1 && v.hits > 0)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] PID={st.Pid} 自动判定已触发 {v.hits} 次（钓鱼小游戏已自动完成）");
                    Log.Write($"自动判定已触发 PID={st.Pid} {v.hits} 次");
                }
                if (v.fishCount != st.LastFishCount && st.LastFishCount != -1 && v.fishCount > 0)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] PID={st.Pid} 本次已自动钓获 {v.fishCount} 条（已入包）");
                    Log.Write($"本次已自动钓获 PID={st.Pid} {v.fishCount} 条");
                }
                if (v.bagFull != st.LastBagFull && st.LastBagFull != -1)
                {
                    string msg = v.bagFull == 1
                        ? $"PID={st.Pid} 背包已满（第 {v.fishCount} 条），自动停下。整理背包后自动恢复循环。"
                        : $"PID={st.Pid} 背包已恢复空间，自动循环继续。";
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {msg}");
                    Log.Write(msg);
                }
                // 入口计数变化（v1.0.2 诊断）：>0 表示游戏确实执行到对应 Hook 点入口
                if (v.entryA != st.LastEntryA && st.LastEntryA != -1 && v.entryA > 0)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] PID={st.Pid} 入口 A（0x38A860 节奏判定）已执行 {v.entryA} 次");
                    Log.Write($"入口 A 已执行 PID={st.Pid} {v.entryA} 次");
                }
                if (v.entryC != st.LastEntryC && st.LastEntryC != -1 && v.entryC > 0)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] PID={st.Pid} 入口 C（0x216C9C 续竿/重甩）已执行 {v.entryC} 次");
                    Log.Write($"入口 C 已执行 PID={st.Pid} {v.entryC} 次");
                }
                if (v.entryD != st.LastEntryD && st.LastEntryD != -1 && v.entryD > 0)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] PID={st.Pid} 入口 D（0x216B46 入包/背包满）已执行 {v.entryD} 次");
                    Log.Write($"入口 D 已执行 PID={st.Pid} {v.entryD} 次");
                }
                if (v.entryE != st.LastEntryE && st.LastEntryE != -1 && v.entryE > 0)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] PID={st.Pid} 入口 E（0x215D2B state2 自动拉线）已执行 {v.entryE} 次");
                    Log.Write($"入口 E 已执行 PID={st.Pid} {v.entryE} 次");
                }

                st.LastEnabled = v.enabled;
                st.LastHits = v.hits;
                st.LastFishCount = v.fishCount;
                st.LastBagFull = v.bagFull;
                st.LastEntryA = v.entryA;
                st.LastEntryC = v.entryC;
                st.LastEntryD = v.entryD;
                st.LastEntryE = v.entryE;

                // Hook B 自愈：确保其字节与 gEnabled 一致（防 F8 切换丢失/二进制被外部覆盖）
                try
                {
                    string sync = Injector.SyncHookB(handle.Handle, st.Pid, st.ModuleBase, v.enabled == 1);
                    if (sync.StartsWith("Hook B →"))
                    {
                        Console.WriteLine($"  [自愈 PID={st.Pid}] " + sync);
                        Log.Write($"Hook B 自愈 PID={st.Pid}: " + sync);
                    }
                }
                catch (Exception ex)
                {
                    Log.Write($"Hook B 自愈异常 PID={st.Pid}: " + ex.Message);
                }

                // 每约 10 秒自检一次五个 Hook 点是否仍在位；失败（旧版本注入缺 Hook E / 字节被外部覆盖）则自动重新注入
                if (++st.SelfTick % 20 == 0)
                {
                    string check = Injector.Verify(handle.Handle, st.Pid, st.ModuleBase);
                    if (!check.StartsWith("Hook A/B/C/D/E 均在位"))
                    {
                        Console.WriteLine($"[监控 PID={st.Pid}] " + check);
                        Log.Write($"自检 PID={st.Pid}: " + check);
                        // 升级兼容（v1.0.3 → v1.0.4）：旧实例是被 v1.0.3 注入的，缺 Hook E；
                        // 也覆盖 Hook 字节被外部工具覆盖的情形。重新注入前 Install 内部会先还原本模块旧补丁。
                        // 防死循环：自检周期约 10 秒，距上次重注入不足 15 秒则跳过本次。
                        if (Environment.TickCount - st.LastReinjectAt > 15000)
                        {
                            Console.WriteLine($"[监控 PID={st.Pid}] Verify 未通过，自动重新注入补齐 Hook……");
                            Log.Write($"自动重新注入 PID={st.Pid}");
                            st.LastReinjectAt = Environment.TickCount;
                            InjectInstance(p, st);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// F8 按下沿：对所有已注入实例统一翻转 gEnabled + 同步 Hook B。
        /// 返回翻转后的开关状态（1=开启/0=关闭），无实例可翻转时返回 -1。
        /// </summary>
        public static int FlipAll(Dictionary<long, InstanceState> instances)
        {
            if (instances.Count == 0)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 → 尚无游戏实例，切换无效。");
                return -1;
            }

            int switched = -1;
            int flipped = 0;
            foreach (var st in instances.Values)
            {
                if (!st.Injected) continue;
                try
                {
                    using (var p = Process.GetProcessById((int)st.Pid))
                    using (var handle = new SafeProcessHandle(p))
                    {
                        int newState = Injector.ToggleEnabled(handle.Handle, st.Pid);
                        if (newState < 0)
                        {
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 → PID={st.Pid} 状态不可读，等待自动重注。");
                            Log.Write($"F8 切换失败 PID={st.Pid}");
                            continue;
                        }
                        string txt = newState == 1 ? "已开启自动钓鱼（甩竿后自动循环）" : "已关闭自动钓鱼（完全原版）";
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] F8 → PID={st.Pid} {txt}");
                        Log.Write($"F8 切换 PID={st.Pid} → {txt}");

                        string sync = Injector.SyncHookB(handle.Handle, st.Pid, st.ModuleBase, newState == 1);
                        Console.WriteLine("  " + sync);
                        Log.Write($"F8 同步 Hook B PID={st.Pid}: " + sync);

                        st.LastEnabled = newState;
                        switched = newState;
                        flipped++;
                    }
                }
                catch (Exception ex)
                {
                    Log.Write($"F8 翻转实例 PID={st.Pid} 异常: " + ex.Message);
                }
            }

            if (flipped > 0 && switched >= 0)
                Win32Api.Beep(switched == 1 ? 880u : 440u, 100); // 开启 880Hz / 关闭 440Hz，各 100ms
            return switched;
        }
    }
}