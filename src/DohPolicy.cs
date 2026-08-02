using Microsoft.Win32;

namespace Anchor;

/// <summary>
/// Turns browser DNS-over-HTTPS OFF while a lock is active — the SAFE way.
///
/// WHY THIS EXISTS: browsers ship with "Secure DNS" on, which sends DNS lookups over HTTPS
/// straight to a provider and completely skips the Windows hosts file. That's how a browser
/// could still load YouTube when every other program on the PC could not.
///
/// WHY WE DON'T JUST BLOCK THE DoH SERVERS: we tried, and it was a disaster (2026-08-01).
/// A browser set to a specific DoH provider runs in "strict" mode with NO fallback to system
/// DNS, so dropping those packets left the browser unable to resolve ANY site — the machine
/// looked completely offline. Blocking infrastructure is never worth it.
///
/// Instead we set the documented enterprise policy that tells the browser "don't use DoH".
/// The browser then resolves through Windows like everything else, so the hosts file works,
/// and nothing is ever dropped — there is no way for this to strand your DNS.
///
/// Every value we change is backed up first and restored exactly when the lock ends.
/// Note: browsers read policy at startup (and refresh periodically), so a browser that is
/// already running may keep using DoH until it is restarted. The SNI/QUIC filter still
/// covers that gap; this is a defence-in-depth layer, not the only one.
/// </summary>
public static class DohPolicy
{
    // Where we stash the previous values so we can put things back exactly as we found them.
    private const string BackupKey = @"SOFTWARE\Anchor\DohBackup";
    private const string AbsentMarker = "<<absent>>";

    private sealed record PolicyValue(string KeyPath, string Name, RegistryValueKind Kind, object DisabledValue);

    // The documented "turn DoH off" policies for the major browsers.
    private static readonly PolicyValue[] Policies =
    {
        // Chrome: DnsOverHttpsMode = "off"
        new(@"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", RegistryValueKind.String, "off"),
        // Edge: same policy name, different vendor key
        new(@"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", RegistryValueKind.String, "off"),
        // Brave (Chromium-based, honours the Brave policy key)
        new(@"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", RegistryValueKind.String, "off"),
        // Firefox: DNSOverHTTPS -> Enabled = 0, Locked = 1
        new(@"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", RegistryValueKind.DWord, 0),
        new(@"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", RegistryValueKind.DWord, 1),
    };

    /// <summary>Turn DoH off in every supported browser, remembering what was there before.</summary>
    public static void Disable()
    {
        foreach (var p in Policies)
        {
            try
            {
                BackupOnce(p);
                using var key = Registry.LocalMachine.CreateSubKey(p.KeyPath);
                key?.SetValue(p.Name, p.DisabledValue, p.Kind);
            }
            catch (Exception ex)
            {
                // Never fatal: if we can't set a policy, blocking still works via the packet filter.
                Log.Warn($"Could not set DoH policy {p.KeyPath}\\{p.Name}: {ex.Message}");
            }
        }
        Log.Info("Browser DoH policy set to off (restored when the lock ends).");
    }

    /// <summary>Put every value back exactly as it was before we touched it.</summary>
    public static void Restore()
    {
        foreach (var p in Policies)
        {
            try
            {
                string? saved = ReadBackup(p);
                using var key = Registry.LocalMachine.OpenSubKey(p.KeyPath, writable: true);
                if (key == null) continue;

                if (saved == null)
                {
                    // No backup recorded -> we never changed it; leave it alone.
                    continue;
                }
                if (saved == AbsentMarker)
                {
                    key.DeleteValue(p.Name, throwOnMissingValue: false);
                }
                else if (p.Kind == RegistryValueKind.DWord && int.TryParse(saved, out int dw))
                {
                    key.SetValue(p.Name, dw, RegistryValueKind.DWord);
                }
                else
                {
                    key.SetValue(p.Name, saved, RegistryValueKind.String);
                }
            }
            catch (Exception ex)
            {
                Log.Warn($"Could not restore DoH policy {p.KeyPath}\\{p.Name}: {ex.Message}");
            }
        }

        try { Registry.LocalMachine.DeleteSubKeyTree(BackupKey, throwOnMissingSubKey: false); } catch { }
        Log.Info("Browser DoH policy restored.");
    }

    // Save the current value the FIRST time we touch it, so repeated Disable() calls
    // can't overwrite the real original with our own "off".
    private static void BackupOnce(PolicyValue p)
    {
        string slot = BackupSlot(p);
        using var backup = Registry.LocalMachine.CreateSubKey(BackupKey);
        if (backup == null || backup.GetValue(slot) != null) return;

        using var key = Registry.LocalMachine.OpenSubKey(p.KeyPath);
        object? current = key?.GetValue(p.Name);
        backup.SetValue(slot, current?.ToString() ?? AbsentMarker, RegistryValueKind.String);
    }

    private static string? ReadBackup(PolicyValue p)
    {
        using var backup = Registry.LocalMachine.OpenSubKey(BackupKey);
        return backup?.GetValue(BackupSlot(p)) as string;
    }

    private static string BackupSlot(PolicyValue p) => p.KeyPath.Replace('\\', '_') + "__" + p.Name;
}
