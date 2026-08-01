using System.ServiceProcess;

namespace Anchor;

/// <summary>
/// The single entry point. The SAME Anchor.exe behaves differently depending on how
/// it's launched — this keeps everything in one downloadable file:
///
///   Anchor.exe              -> the GUI (what you double-click; auto-elevates to admin)
///   Anchor.exe --service    -> the background blocker service (started by Windows)
///   Anchor.exe --guardian   -> the watchdog service (started by Windows)
///
/// You never type the --service/--guardian forms yourself; Windows does, because the
/// installer registers the services with those arguments.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main(string[] rawArgs)
    {
        var args = rawArgs.Select(a => a.ToLowerInvariant()).ToArray();

        if (args.Contains("--service"))
        {
            ServiceBase.Run(new AnchorService());
            return;
        }

        if (args.Contains("--guardian"))
        {
            ServiceBase.Run(new GuardianService());
            return;
        }

        // Default: show the GUI. With --tray (used by the login task) it starts hidden,
        // so only the system-tray icon appears.
        bool startHidden = args.Contains("--tray") || args.Contains("--minimized");
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(startHidden));
    }
}
