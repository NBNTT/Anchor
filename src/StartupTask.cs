using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;

namespace Anchor;

/// <summary>
/// Makes Anchor's tray GUI start automatically when you log in, so the tray icon reappears
/// on its own after a reboot.
///
/// We use a Windows Scheduled Task (not the Startup folder) because Anchor requires admin
/// rights: a task set to "run with highest privileges" at logon launches the elevated app
/// WITHOUT a UAC prompt every time. The task runs "Anchor.exe --tray", which starts hidden
/// (only the tray icon shows).
///
/// Everything here is done through the built-in `schtasks.exe`, so it's easy to inspect
/// (Task Scheduler > "AnchorTray") and remove.
/// </summary>
public static class StartupTask
{
    public const string TaskName = "AnchorTray";

    /// <summary>Is the login task currently registered?</summary>
    public static bool IsEnabled()
    {
        // schtasks /Query returns exit code 0 if the task exists, 1 if it doesn't.
        return RunSchtasks($"/Query /TN \"{TaskName}\"", out _) == 0;
    }

    /// <summary>Register (or refresh) the login task to launch the given exe in tray mode.</summary>
    public static void Enable(string exePath)
    {
        string xml = BuildTaskXml(exePath);

        // schtasks wants the XML as a UTF-16 file.
        string tmp = Path.Combine(Path.GetTempPath(), "anchor_startup.xml");
        File.WriteAllText(tmp, xml, Encoding.Unicode);

        try
        {
            int code = RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{tmp}\" /F", out string output);
            if (code != 0)
                throw new InvalidOperationException($"schtasks failed (exit {code}): {output}");
        }
        finally
        {
            try { File.Delete(tmp); } catch { }
        }
        Log.Info("Startup task enabled.");
    }

    /// <summary>Remove the login task.</summary>
    public static void Disable()
    {
        RunSchtasks($"/Delete /TN \"{TaskName}\" /F", out _);
        Log.Info("Startup task removed.");
    }

    /// <summary>
    /// A Task Scheduler definition: at this user's logon, run the exe elevated in their own
    /// interactive session (InteractiveToken = no stored password, no UAC prompt), no time limit.
    /// </summary>
    private static string BuildTaskXml(string exePath)
    {
        string user = XmlEscape(WindowsIdentity.GetCurrent().Name);   // e.g. COMPUTERNAME\username
        string command = XmlEscape(exePath);

        return
$@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>Starts Anchor in the system tray at login.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id=""Author"">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>{command}</Command>
      <Arguments>--tray</Arguments>
    </Exec>
  </Actions>
</Task>";
    }

    private static string XmlEscape(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    private static int RunSchtasks(string arguments, out string output)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            output = (p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()).Trim();
            p.WaitForExit(15000);
            return p.ExitCode;
        }
        catch (Exception ex)
        {
            output = ex.Message;
            return -1;
        }
    }
}
