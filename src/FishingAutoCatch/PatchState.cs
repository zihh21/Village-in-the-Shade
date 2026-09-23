using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FishingAutoCatch
{
    /// <summary>
    /// 补丁状态持久化：记录注入时的模块基址、Hook 目标、stub 基址和原始 15 字节，
    /// 供 --remove 还原与 --status 查询使用。
    /// </summary>
    internal static class PatchState
    {
        private static readonly string FilePath =
            Path.Combine(AppContext.BaseDirectory, "FishingAutoCatch.state");

        public static void Save(long moduleBase, long stubBase, byte[] originalBytes)
        {
            var sb = new StringBuilder();
            sb.Append("moduleBase=").Append(moduleBase.ToString("X")).Append('\n');
            sb.Append("stubBase=").Append(stubBase.ToString("X")).Append('\n');
            sb.Append("original=").Append(Convert.ToBase64String(originalBytes)).Append('\n');
            File.WriteAllText(FilePath, sb.ToString(), new UTF8Encoding(false));
        }

        public static bool TryLoad(out long moduleBase, out long stubBase, out byte[] originalBytes)
        {
            moduleBase = 0; stubBase = 0; originalBytes = null;
            if (!File.Exists(FilePath)) return false;
            var lines = File.ReadAllLines(FilePath, Encoding.UTF8);
            var map = new Dictionary<string, string>();
            foreach (var line in lines)
            {
                int i = line.IndexOf('=');
                if (i > 0) map[line.Substring(0, i)] = line.Substring(i + 1);
            }
            if (!map.TryGetValue("moduleBase", out var m) ||
               !map.TryGetValue("stubBase", out var s) ||
               !map.TryGetValue("original", out var o)) return false;

            bool ok = long.TryParse(m, System.Globalization.NumberStyles.HexNumber, null, out moduleBase) &&
                      long.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out stubBase);
            if (!ok) return false;
            try { originalBytes = Convert.FromBase64String(o); }
            catch (FormatException) { return false; }
            return originalBytes.Length == HookStub.PatchLength;
        }
    }
}