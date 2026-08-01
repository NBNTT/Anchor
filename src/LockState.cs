using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Anchor;

/// <summary>
/// The commitment timer — the reason the block is hard to turn off.
///
/// KEY IDEA (why the clock can't be cheated): we do NOT count down using the wall
/// clock. We count "active seconds" that only accumulate while the service is actually
/// running, measured with a monotonic stopwatch. Setting your PC's clock forward does
/// nothing. The lock ends only when enough real running-time has passed.
///
/// The state is stored in TWO places (an encrypted file AND the registry). On load we
/// take whichever is MORE locked, so deleting one copy does not unlock you.
///
/// Safety cap: a single lock can never exceed 7 days of active time (see MaxSeconds),
/// and Safe Mode always disables the service — so you can never truly brick yourself.
/// </summary>
public sealed class LockState
{
    // 7 days, in seconds. The hard ceiling on any one lock.
    private const long MaxSeconds = 7L * 24 * 3600;
    private const long MinSeconds = 60; // don't allow silly 0-second "locks"

    // ---- Persisted fields (saved to disk/registry) ----
    public bool Active { get; set; }
    public long RequiredSeconds { get; set; }
    public long AccumulatedSeconds { get; set; }
    public DateTime StartedUtc { get; set; }

    // ---- Computed helpers (not saved) ----
    [JsonIgnore] public long RemainingSeconds => Math.Max(0, RequiredSeconds - AccumulatedSeconds);
    [JsonIgnore] public TimeSpan Remaining => TimeSpan.FromSeconds(RemainingSeconds);
    [JsonIgnore] public bool IsLocked => Active && RemainingSeconds > 0;

    /// <summary>Start a new lock, or EXTEND an existing one. You can only ever make it longer.</summary>
    public void StartOrExtend(TimeSpan duration)
    {
        long secs = Math.Clamp((long)duration.TotalSeconds, MinSeconds, MaxSeconds);

        if (!IsLocked)
        {
            Active = true;
            RequiredSeconds = secs;
            AccumulatedSeconds = 0;
            StartedUtc = DateTime.UtcNow;
        }
        else if (secs > RemainingSeconds)
        {
            // Extending: keep progress so far, just push the finish line out.
            RequiredSeconds = AccumulatedSeconds + secs;
        }
        // If a shorter time is requested while locked, we ignore it — you can't shorten a lock.
    }

    /// <summary>
    /// Add real running-time. <paramref name="elapsedSeconds"/> comes from a monotonic stopwatch,
    /// and we clamp it so a weird pause can never fast-forward the countdown.
    /// </summary>
    public void Tick(long elapsedSeconds)
    {
        if (!IsLocked) return;
        AccumulatedSeconds += Math.Clamp(elapsedSeconds, 0, 120);
        if (AccumulatedSeconds >= RequiredSeconds)
        {
            AccumulatedSeconds = RequiredSeconds;
            Active = false; // lock complete
        }
    }

    // ===================== Persistence =====================

    private const string RegKey = @"SOFTWARE\Anchor";
    private const string RegValue = "State";

    /// <summary>Load the state, taking whichever stored copy is more locked. Never throws.</summary>
    public static LockState Load()
    {
        LockState? fromFile = TryDecrypt(TryReadFileBytes());
        LockState? fromReg = TryDecrypt(TryReadRegistryBytes());
        return MoreLocked(fromFile, fromReg) ?? new LockState();
    }

    /// <summary>Encrypt and write the state to BOTH the file and the registry.</summary>
    public void Save()
    {
        try
        {
            byte[] plain = JsonSerializer.SerializeToUtf8Bytes(this);
            byte[] enc = ProtectedData.Protect(plain, null, DataProtectionScope.LocalMachine);

            AppPaths.EnsureDataDir();
            File.WriteAllBytes(AppPaths.StateFile, enc);

            using var key = Registry.LocalMachine.CreateSubKey(RegKey);
            key?.SetValue(RegValue, enc, RegistryValueKind.Binary);
        }
        catch (Exception ex)
        {
            Log.Error("Could not save lock state: " + ex.Message);
        }
    }

    /// <summary>Clear the lock completely (used only when unlocked, e.g. before uninstall).</summary>
    public static void Clear()
    {
        try { if (File.Exists(AppPaths.StateFile)) File.Delete(AppPaths.StateFile); } catch { }
        try { Registry.LocalMachine.DeleteSubKeyTree(RegKey, throwOnMissingSubKey: false); } catch { }
    }

    // Return the copy that keeps the user locked longer (or the only non-null one).
    private static LockState? MoreLocked(LockState? a, LockState? b)
    {
        if (a == null) return b;
        if (b == null) return a;
        if (a.IsLocked != b.IsLocked) return a.IsLocked ? a : b;
        return a.RemainingSeconds >= b.RemainingSeconds ? a : b;
    }

    private static LockState? TryDecrypt(byte[]? enc)
    {
        if (enc == null || enc.Length == 0) return null;
        try
        {
            byte[] plain = ProtectedData.Unprotect(enc, null, DataProtectionScope.LocalMachine);
            return JsonSerializer.Deserialize<LockState>(plain);
        }
        catch
        {
            return null; // corrupt or from another machine: ignore this copy
        }
    }

    private static byte[]? TryReadFileBytes()
    {
        try { return File.Exists(AppPaths.StateFile) ? File.ReadAllBytes(AppPaths.StateFile) : null; }
        catch { return null; }
    }

    private static byte[]? TryReadRegistryBytes()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegKey);
            return key?.GetValue(RegValue) as byte[];
        }
        catch { return null; }
    }
}
