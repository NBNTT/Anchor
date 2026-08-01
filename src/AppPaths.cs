using System.IO;

namespace Anchor;

/// <summary>
/// One place that knows WHERE everything lives. Centralizing this means you can
/// audit every file/registry name Anchor touches by reading this one file.
/// </summary>
public static class AppPaths
{
    // The two Windows service names. "Anchor" does the blocking; "AnchorGuardian" restarts it if killed.
    public const string ServiceName = "Anchor";
    public const string GuardianName = "AnchorGuardian";

    // Where the installed copy of the program lives (Program Files, so a normal user can't casually delete it).
    public static string InstallDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Anchor");

    public static string InstalledExe => Path.Combine(InstallDir, "Anchor.exe");

    // ProgramData = machine-wide data that survives user profile changes. The lock state lives here, encrypted.
    public static string DataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Anchor");

    public static string StateFile => Path.Combine(DataDir, "state.dat"); // DPAPI-encrypted lock timer
    public static string LogFile => Path.Combine(DataDir, "anchor.log");

    // The real Windows hosts file (our secondary, belt-and-suspenders block layer).
    public static string HostsFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>Make sure the ProgramData folder exists before we read/write state.</summary>
    public static void EnsureDataDir() => Directory.CreateDirectory(DataDir);
}
