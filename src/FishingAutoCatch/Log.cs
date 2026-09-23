using System;
using System.IO;
using System.Text;

namespace FishingAutoCatch
{
    /// <summary>
    /// 简单日志：追加写入 exe 同目录的 FishingAutoCatch.log（UTF-8 无 BOM）。
    /// 双击运行时控制台窗口信息一闪而过，日志便于事后排查注入是否成功。
    /// </summary>
    internal static class Log
    {
        private static readonly object Gate = new object();
        private static readonly string FilePath =
            Path.Combine(AppContext.BaseDirectory, "FishingAutoCatch.log");

        public static void Write(string message)
        {
            try
            {
                lock (Gate)
                {
                    File.AppendAllText(FilePath,
                        $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}",
                        new UTF8Encoding(false));
                }
            }
            catch
            {
                // 日志写入失败不影响主流程
            }
        }

        public static void Write(string message, Exception ex)
        {
            Write(message + "\n" + ex);
        }
    }
}