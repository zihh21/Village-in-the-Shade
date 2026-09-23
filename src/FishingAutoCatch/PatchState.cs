using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FishingAutoCatch
{
    /// <summary>
    /// 补丁状态持久化（v1.0.3 起按进程 PID 分文件）：
    /// 每个游戏实例写入 FishingAutoCatch.state.&lt;pid&gt;，记录该实例注入时的模块基址、stub 基址、
    /// Hook 点 A/B/C/D/E 的原始字节，供 --remove 还原与监控模式使用。
    ///
    /// 为什么按 PID 分文件（v1.0.3 修复"重启游戏后 Mod 不生效"的根因之一）：
    /// 游戏 PE 关闭 ASLR，多个实例的 moduleBase 完全相同（本会话两个实例均为 0x7FF66AA00000），
    /// 旧版单文件只用 moduleBase 标识进程，多实例时互相覆盖，导致监控只注入/管理最早发现的实例，
    /// 用户在后来启动的实例里游玩时 Hook 完全缺失。改用 PID 后每个实例独立记录、互不干扰。
    ///
    /// 兼容旧版：无 &lt;pid&gt; 文件时回退读取旧单文件 FishingAutoCatch.state
    /// （moduleBase 仍由调用方结合当前进程校验），保证旧版本注入过的实例可被识别与还原。
    /// </summary>
    internal static class PatchState
    {
        /// <summary>按进程 PID 的补丁状态文件路径。</summary>
        public static string FilePathFor(long pid) =>
            Path.Combine(AppContext.BaseDirectory, $"FishingAutoCatch.state.{pid}");

        /// <summary>旧版单文件路径（v1.0.2 及更早）。</summary>
        private static readonly string LegacyFilePath =
            Path.Combine(AppContext.BaseDirectory, "FishingAutoCatch.state");

        public static void Save(long pid, long moduleBase, long stubBase,
            byte[] originalA, byte[] originalB, byte[] originalC, byte[] originalD,
            byte[] originalE)
        {
            var sb = new StringBuilder();
            sb.Append("pid=").Append(pid).Append('\n');
            sb.Append("moduleBase=").Append(moduleBase.ToString("X")).Append('\n');
            sb.Append("stubBase=").Append(stubBase.ToString("X")).Append('\n');
            sb.Append("original=").Append(originalA == null ? "" : Convert.ToBase64String(originalA)).Append('\n');
            sb.Append("original2=").Append(originalB == null ? "" : Convert.ToBase64String(originalB)).Append('\n');
            sb.Append("original3=").Append(originalC == null ? "" : Convert.ToBase64String(originalC)).Append('\n');
            sb.Append("original4=").Append(originalD == null ? "" : Convert.ToBase64String(originalD)).Append('\n');
            sb.Append("original5=").Append(originalE == null ? "" : Convert.ToBase64String(originalE)).Append('\n');
            File.WriteAllText(FilePathFor(pid), sb.ToString(), new UTF8Encoding(false));
        }

        /// <summary>
        /// 读取某进程的注入状态。优先读 FishingAutoCatch.state.&lt;pid&gt;；
        /// 不存在时回退旧版单文件（返回 true，由调用方按 moduleBase 校验归属）。
        /// 输出：moduleBase / stubBase / originalA..originalE（Hook 点 A/B/C/D/E 原字节，可空）。
        /// </summary>
        public static bool TryLoad(long pid, out long moduleBase, out long stubBase,
            out byte[] originalA, out byte[] originalB, out byte[] originalC, out byte[] originalD,
            out byte[] originalE)
        {
            moduleBase = 0; stubBase = 0; originalA = null; originalB = null;
            originalC = null; originalD = null; originalE = null;

            var perPid = FilePathFor(pid);
            if (File.Exists(perPid))
                return TryParse(perPid, out moduleBase, out stubBase,
                    out originalA, out originalB, out originalC, out originalD, out originalE);
            if (File.Exists(LegacyFilePath))
                return TryParse(LegacyFilePath, out moduleBase, out stubBase,
                    out originalA, out originalB, out originalC, out originalD, out originalE);
            return false;
        }

        /// <summary>解析 state 文件文本；格式非法时返回 false。</summary>
        private static bool TryParse(string path, out long moduleBase, out long stubBase,
            out byte[] originalA, out byte[] originalB, out byte[] originalC, out byte[] originalD,
            out byte[] originalE)
        {
            moduleBase = 0; stubBase = 0; originalA = null; originalB = null;
            originalC = null; originalD = null; originalE = null;

            string[] lines;
            try { lines = File.ReadAllLines(path, Encoding.UTF8); }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }

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

            originalA = Decode(map, "original", HookStub.PatchLength);
            originalB = Decode(map, "original2", HookStub.SuccessPatchLength);
            originalC = Decode(map, "original3", HookStub.CastPatchLength);
            originalD = Decode(map, "original4", HookStub.BagPatchLength);
            originalE = Decode(map, "original5", HookStub.HookEPatchLength);
            return true;
        }

        /// <summary>Base64 解码某 key 的原始字节；缺失/长度不符时返回 null。</summary>
        private static byte[] Decode(Dictionary<string, string> map, string key, int expectLen)
        {
            if (!map.TryGetValue(key, out var o) || string.IsNullOrEmpty(o)) return null;
            try
            {
                var b = Convert.FromBase64String(o);
                return b.Length == expectLen ? b : null;
            }
            catch (FormatException) { return null; }
        }
    }
}