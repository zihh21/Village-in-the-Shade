using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace FishingAutoCatch
{
    /// <summary>定位正在运行的游戏进程并取得模块基址。</summary>
    internal static class ProcessManager
    {
        /// <summary>
        /// 枚举所有 village.exe 实例（v1.0.3 多实例支持）。
        /// 游戏重启/双开时可能存在多个实例，监控模式需要对每个实例都注入并管理，
        /// 否则用户在后来启动的实例里游玩时会因为缺少 Hook 而"Mod 完全不生效"（v1.0.2 根因）。
        /// 排序：按启动时间升序（旧 → 新），调用方可取最后一个得到"最新实例"。
        /// </summary>
        public static List<Process> FindAllVillageProcesses()
        {
            var list = new List<Process>();
            Process[] procs;
            try { procs = Process.GetProcessesByName("village"); }
            catch { return list; }

            foreach (var p in procs)
            {
                try
                {
                    // 触发必要的句柄打开，校验进程可访问性
                    _ = p.Handle;
                    list.Add(p);
                }
                catch
                {
                    p.Dispose();
                }
            }
            list.Sort((x, y) => x.StartTime.CompareTo(y.StartTime));
            return list;
        }

        /// <summary>查找正在运行且"最新启动"的 village.exe 实例（进化为钓鱼场景的可能性最大）。</summary>
        public static Process FindVillageProcess()
        {
            var list = FindAllVillageProcesses();
            if (list.Count == 0) return null;

            // 返回最后一个（最新启动）；释放其余进程对象
            var last = list[list.Count - 1];
            for (int i = 0; i < list.Count - 1; i++) list[i].Dispose();
            return last;
        }

        /// <summary>读取进程主模块基址（PE ImageBase，ASLR 感知）。</summary>
        public static long GetModuleBase(Process p)
        {
            try
            {
                return p.MainModule.BaseAddress.ToInt64();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("无法读取进程主模块基址，请确认已以管理员或同一用户权限运行。" + ex.Message, ex);
            }
        }
    }
}