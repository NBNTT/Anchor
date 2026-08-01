using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

namespace Anchor;

/// <summary>
/// Installs, removes, and hardens the two Windows services. All the "hard to remove"
/// plumbing lives here, and every trick is a plain `sc.exe` command you can read and
/// (from Safe Mode) undo. See RECOVERY.md.
///
/// The services:
///   Anchor          - runs the FilterEngine (the actual blocking)
///   AnchorGuardian  - tiny watchdog that restarts Anchor if it's killed
/// Both are set to auto-start at boot and to auto-restart on failure.
///
/// HARDENING (only applied while a lock is active): we set the service security
/// descriptor to DENY "stop" and "delete" to everyone, so `net stop`, Services.msc,
/// and Task Manager all fail. An administrator can still recover deliberately (reset
/// the descriptor, or Safe Mode) — this is friction, not an unbreakable wall.
/// </summary>
public static class ServiceControl
{
    // Files that must travel together (Anchor.exe + the WinDivert driver/library).
    private static readonly string[] PayloadFiles = { "Anchor.exe", "WinDivert.dll", "WinDivert64.sys" };

    // Security descriptor that DENIES stop (WP) + delete (SD) to Everyone (WD), while leaving
    // the normal allow-ACEs so the service still runs and can be queried. Deny wins, so nobody
    // can casually stop/delete it. (Admins keep WRITE_DAC, so a deliberate reset is still possible.)
    private const string HardenedSddl =
        "D:(D;;WPSD;;;WD)" +
        "(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
        "(A;;CCLCSWLOCRRC;;;IU)" +
        "(A;;CCLCSWLOCRRC;;;SU)";

    // The normal, unhardened descriptor (what a service has by default). Used to un-harden/uninstall.
    private const string DefaultSddl =
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
        "(A;;CCLCSWLOCRRC;;;IU)" +
        "(A;;CCLCSWLOCRRC;;;SU)";

    // ===================== install / uninstall =====================

    public static bool IsInstalled() => ServiceExists(AppPaths.ServiceName);

    /// <summary>
    /// Copy the program into Program Files and register both services (auto-start + auto-restart).
    /// Safe to call repeatedly; it just re-ensures everything is in place.
    /// </summary>
    public static void Install()
    {
        CopyPayloadToProgramFiles();

        string exe = AppPaths.InstalledExe;

        if (!ServiceExists(AppPaths.ServiceName))
        {
            RunSc($"create {AppPaths.ServiceName} binPath= \"\\\"{exe}\\\" --service\" start= auto DisplayName= \"Anchor Website Blocker\"");
            RunSc($"description {AppPaths.ServiceName} \"Blocks distracting websites. Part of the Anchor self-control tool.\"");
            // On failure, restart after 5s, forever. reset= 0 means the failure counter never resets.
            RunSc($"failure {AppPaths.ServiceName} reset= 0 actions= restart/5000/restart/5000/restart/5000");
        }

        if (!ServiceExists(AppPaths.GuardianName))
        {
            RunSc($"create {AppPaths.GuardianName} binPath= \"\\\"{exe}\\\" --guardian\" start= auto DisplayName= \"Anchor Guardian\"");
            RunSc($"description {AppPaths.GuardianName} \"Watchdog that keeps the Anchor blocker running.\"");
            RunSc($"failure {AppPaths.GuardianName} reset= 0 actions= restart/5000/restart/5000/restart/5000");
        }

        RunSc($"start {AppPaths.ServiceName}");
        RunSc($"start {AppPaths.GuardianName}");
        Log.Info("Services installed and started.");
    }

    /// <summary>
    /// Fully remove Anchor. This should only ever run when NOT locked (the GUI enforces that).
    /// It un-hardens, stops, deletes both services, and cleans up the hosts file + saved state.
    /// </summary>
    public static void Uninstall()
    {
        Unharden(); // restore normal permissions so we're allowed to stop/delete

        foreach (var name in new[] { AppPaths.ServiceName, AppPaths.GuardianName })
        {
            RunSc($"stop {name}");
            RunSc($"delete {name}");
        }

        HostsFile.Remove();
        LockState.Clear();
        StartupTask.Disable();   // also remove the "start at login" task if it was set

        // Unload the WinDivert kernel driver so WinDivert64.sys unlocks (otherwise the folder
        // can't be deleted, and a later reinstall can't overwrite the .sys).
        RunSc("stop WinDivert");
        RunSc("delete WinDivert");

        // Best effort: remove the installed files. The currently-running exe may be locked;
        // whatever we can't delete now is harmless (the services are already gone).
        TryDeleteInstallDir();
        Log.Info("Anchor uninstalled.");
    }

    // ===================== auto-update on launch =====================

    /// <summary>What happened when we checked for a newer build at launch.</summary>
    public enum UpdateResult
    {
        NotNeeded,      // already up to date (or we're running the installed copy itself)
        Updated,        // the background service was replaced with this newer build
        BlockedByLock,  // a newer build is ready, but a lock is active so we left everything alone
    }

    /// <summary>
    /// If you launch a NEWER Anchor.exe than the one installed as the background service,
    /// quietly replace the installed copy so the service picks up the new code — no manual
    /// uninstall/reinstall dance.
    ///
    /// TWO DELIBERATE GUARDS:
    ///  1. We NEVER update while a lock is active. Updating means stopping the services, which
    ///     would both interrupt blocking and hand you an obvious bypass ("swap in a harmless
    ///     Anchor.exe, relaunch, done"). While locked we do nothing and report BlockedByLock.
    ///  2. We only ever move FORWARD (the launched file must be newer than the installed one),
    ///     so running an old copy from your Downloads folder can't silently downgrade you.
    /// </summary>
    public static UpdateResult TryAutoUpdate()
    {
        string srcExe = Environment.ProcessPath!;
        string srcDir = Path.GetDirectoryName(srcExe) ?? "";
        string dstExe = AppPaths.InstalledExe;

        // Running the installed copy itself? Then there is nothing to update.
        if (string.Equals(Path.TrimEndingDirectorySeparator(srcDir),
                          Path.TrimEndingDirectorySeparator(AppPaths.InstallDir),
                          StringComparison.OrdinalIgnoreCase))
            return UpdateResult.NotNeeded;

        if (!File.Exists(dstExe)) return UpdateResult.NotNeeded;   // not installed yet; Install() covers it
        if (!FilesDiffer(srcExe, dstExe)) return UpdateResult.NotNeeded;
        if (File.GetLastWriteTimeUtc(srcExe) <= File.GetLastWriteTimeUtc(dstExe))
            return UpdateResult.NotNeeded;                          // guard 2: never downgrade

        if (LockState.Load().IsLocked)                              // guard 1: never touch a live lock
        {
            Log.Info("A newer Anchor build is available, but a lock is active — update deferred.");
            return UpdateResult.BlockedByLock;
        }

        Log.Info("Newer Anchor build detected; updating the background service.");

        // Stop both services so the installed exe is no longer locked, then reinstall in place.
        Unharden();
        StopAndWait(AppPaths.GuardianName);
        StopAndWait(AppPaths.ServiceName);
        WaitUntilWritable(dstExe, 5000);

        Install();   // idempotent: copies the new files, (re)creates if needed, starts both
        Log.Info("Update complete.");
        return UpdateResult.Updated;
    }

    /// <summary>Stop a service and wait for it to actually reach Stopped (best effort).</summary>
    private static void StopAndWait(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            if (sc.Status != ServiceControllerStatus.Stopped)
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
            }
        }
        catch { /* not installed, already stopped, or timed out — the write check below decides */ }
    }

    /// <summary>Poll until we can open the file for writing (i.e. the process holding it exited).</summary>
    private static void WaitUntilWritable(string path, int timeoutMs)
    {
        var until = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < until)
        {
            try
            {
                using var fs = File.Open(path, FileMode.Open, FileAccess.Write, FileShare.None);
                return;
            }
            catch (IOException) { Thread.Sleep(200); }
            catch { return; }   // some other problem: let the copy surface the real error
        }
    }

    /// <summary>Compare two files by content hash (cheap enough at ~50 MB, and exact).</summary>
    private static bool FilesDiffer(string a, string b)
    {
        try
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var fa = File.OpenRead(a);
            using var fb = File.OpenRead(b);
            return !sha.ComputeHash(fa).AsSpan().SequenceEqual(sha.ComputeHash(fb));
        }
        catch
        {
            return false;   // can't tell -> assume same -> do nothing (safe default)
        }
    }

    private static bool IsWinDivertFile(string fileName) =>
        fileName.StartsWith("WinDivert", StringComparison.OrdinalIgnoreCase);

    // ===================== hardening (called by the service on lock/unlock) =====================

    public static void Harden()
    {
        RunSc($"sdset {AppPaths.ServiceName} {HardenedSddl}");
        RunSc($"sdset {AppPaths.GuardianName} {HardenedSddl}");
        Log.Info("Services hardened (stop/delete denied).");
    }

    public static void Unharden()
    {
        RunSc($"sdset {AppPaths.ServiceName} {DefaultSddl}");
        RunSc($"sdset {AppPaths.GuardianName} {DefaultSddl}");
        Log.Info("Services un-hardened (normal permissions restored).");
    }

    // ===================== small helpers =====================

    public static bool ServiceExists(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            _ = sc.Status; // touching Status throws if the service doesn't exist
            return true;
        }
        catch { return false; }
    }

    public static bool IsRunning(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch { return false; }
    }

    public static void EnsureRunning(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            if (sc.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
                sc.Start();
        }
        catch { /* service may not exist yet; ignore */ }
    }

    private static void CopyPayloadToProgramFiles()
    {
        // Environment.ProcessPath is the REAL exe location, which is correct even for a
        // single-file published exe (AppContext.BaseDirectory can point at a temp folder).
        string sourceDir = Path.GetDirectoryName(Environment.ProcessPath!) ?? AppContext.BaseDirectory;
        // If we're already running from the install dir, there's nothing to copy.
        if (string.Equals(Path.TrimEndingDirectorySeparator(sourceDir),
                          Path.TrimEndingDirectorySeparator(AppPaths.InstallDir),
                          StringComparison.OrdinalIgnoreCase))
            return;

        Directory.CreateDirectory(AppPaths.InstallDir);
        foreach (var file in PayloadFiles)
        {
            string src = Path.Combine(sourceDir, file);
            if (!File.Exists(src)) continue;
            string dst = Path.Combine(AppPaths.InstallDir, file);
            try
            {
                File.Copy(src, dst, overwrite: true);
            }
            catch (IOException) when (IsWinDivertFile(file) && File.Exists(dst))
            {
                // WinDivert64.sys stays locked while its kernel driver is loaded. Those files
                // come from a fixed WinDivert release and are identical across Anchor versions,
                // so keeping the copy already on disk is safe.
                //
                // NOTE: this tolerance deliberately does NOT cover Anchor.exe. If our own exe
                // can't be replaced, the update did not happen and the caller must hear about
                // it — silently keeping a stale binary would make auto-update lie.
                Log.Warn($"Could not overwrite {file} (in use); keeping the existing copy.");
            }
        }
    }

    private static void TryDeleteInstallDir()
    {
        try
        {
            if (Directory.Exists(AppPaths.InstallDir))
                Directory.Delete(AppPaths.InstallDir, recursive: true);
        }
        catch { /* running exe may be locked; leftover files are harmless */ }
    }

    /// <summary>Run one `sc.exe` command. Returns the exit code; logs anything unusual.</summary>
    private static int RunSc(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            string outp = p.StandardOutput.ReadToEnd();
            string err = p.StandardError.ReadToEnd();
            p.WaitForExit(15000);

            // sc returns 0 on success; 1060 = "service does not exist", 1056 = "already running", etc.
            if (p.ExitCode != 0 && p.ExitCode != 1056 && p.ExitCode != 1060)
                Log.Warn($"sc {arguments} -> exit {p.ExitCode} {outp.Trim()} {err.Trim()}");
            return p.ExitCode;
        }
        catch (Exception ex)
        {
            Log.Error($"sc {arguments} failed: {ex.Message}");
            return -1;
        }
    }
}
