using System.IO;

namespace Anchor;

/// <summary>
/// Dead-simple append-to-a-file logger. The background service has no console,
/// so this file (C:\ProgramData\Anchor\anchor.log) is how you see what it did.
/// It never throws — logging must never crash the blocker.
/// </summary>
public static class Log
{
    private static readonly object _gate = new();

    public static void Info(string message) => Write("INFO", message);
    public static void Warn(string message) => Write("WARN", message);
    public static void Error(string message) => Write("ERROR", message);

    private static void Write(string level, string message)
    {
        try
        {
            AppPaths.EnsureDataDir();
            string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}{Environment.NewLine}";
            lock (_gate)
            {
                File.AppendAllText(AppPaths.LogFile, line);
            }
        }
        catch
        {
            // Swallow: if we can't log, we still must keep blocking.
        }
    }
}
