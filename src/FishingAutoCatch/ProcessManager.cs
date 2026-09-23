using System;
using System.Diagnostics;

namespace FishingAutoCatch
{
    /// <summary>定位正在运行的游戏进程并取得模块基址。</summary>
    internal static class ProcessManager
    {
        /// <summary>查找正在运行的 village.exe 进程（进程名"village"）。</summary>
        public static Process FindVillageProcess()
        {
            var procs = Process.GetProcessesByName("village");
            foreach (var p in procs)
            {
                try
                {
                    // 触发必要的句柄打开，校验进程可访问性
                    _ = p.Handle;
                    return p;
                }
                catch
                {
                    p.Dispose();
                }
            }
            return null;
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