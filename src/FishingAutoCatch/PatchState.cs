using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FishingAutoCatch
{
    /// <summary>
    /// 补丁状态持久化：记录注入时的模块基址、stub 基址、Hook 点 A（入口 15 字节）
    /// 与 Hook 点 B（成功检查 6 字节）的原始字节，供 --remove 还原与监控模式使用。
    /// </summary>
    internal static class PatchState
    {
        private static readonly string FilePath =
            Path.Combine(AppContext.BaseDirectory, "FishingAutoCatch.state");

        public static void Save(long moduleBase, long stubBase, byte[] originalA, byte[] originalB)
        {
            var sb = new StringBuilder();
            sb.Append("moduleBase=").Append(moduleBase.ToString("X")).Append('\n');
            sb.Append("stubBase=").Append(stubBase.ToString("X")).Append('\n');
            sb.Append("original=").Append(originalA == null ? "" : Convert.ToBase64String(originalA)).Append('\n');
            sb.Append("original2=").Append(originalB == null ? "" : Convert.ToBase64String(originalB)).Append('\n');
            File.WriteAllText(FilePath, sb.ToString(), new UTF8Encoding(false));
        }

        /// <summary>
        /// 读取注入状态。输出：moduleBase / stubBase / originalA（Hook 点 A 原字节，可空）
        /// / originalB（Hook 点 B 原字节，可空）。兼容 v0.1.x/0.2.x 的旧格式（无 original2）。
        /// </summary>
        public static bool TryLoad(out long moduleBase, out long stubBase,
            out byte[] originalA, out byte[] originalB)
        {
            moduleBase = 0; stubBase = 0; originalA = null; originalB = null;
            if (!File.Exists(FilePath)) return false;
            var lines = File.ReadAllLines(FilePath, Encoding.UTF8);
            var map = new Dictionary<string, string>();
            foreach (var line in lines)
            {
                int i = line.IndexOf('=');
                if (i > 0) map[line.Substring(0, i)] = line.Substring(i + 1);
            }
            if (!map.TryGetValue("moduleBase", out var m) ||
               !map.TryGetValue("stubBase", out var s)) return false;

            bool ok = long.TryParse(m, System.Globalization.NumberStyles.HexNumber, null, out moduleBase) &&
                      long.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out stubBase);
            if (!ok) return false;

            if (map.TryGetValue("original", out var o) && !string.IsNullOrEmpty(o))
            {
                try
                {
                    originalA = Convert.FromBase64String(o);
                    if (originalA.Length != HookStub.PatchLength) originalA = null;
                }
                catch (FormatException) { originalA = null; }
            }
            if (map.TryGetValue("original2", out var o2) && !string.IsNullOrEmpty(o2))
            {
                try
                {
                    originalB = Convert.FromBase64String(o2);
                    if (originalB.Length != HookStub.SuccessPatchLength) originalB = null;
                }
                catch (FormatException) { originalB = null; }
            }
            return true;
        }
    }
}