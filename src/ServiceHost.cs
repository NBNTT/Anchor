using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

namespace Anchor;

/// <summary>
/// The "Anchor" service: the background process that actually enforces the block.
/// Windows starts it at boot. Its worker loop owns the lock timer and turns the
/// FilterEngine on/off. See ServiceWorker below for the real logic.
/// </summary>
public sealed class AnchorService : ServiceBase
{
    private ServiceWorker? _worker;

    public AnchorService() => ServiceName = AppPaths.ServiceName;

    protected override void OnStart(string[] args)
    {
        _worker = new ServiceWorker(guardianMode: false);
        _worker.Start();
    }

    protected override void OnStop() => _worker?.Stop();
}

/// <summary>
/// The "AnchorGuardian" service: a tiny watchdog. Its only job is to make sure the
/// Anchor service is running, restarting it within a few seconds if it gets killed.
/// (Anchor returns the favor and keeps the guardian alive — a mutual watchdog.)
/// </summary>
public sealed class GuardianService : ServiceBase
{
    private ServiceWorker? _worker;

    public GuardianService() => ServiceName = AppPaths.GuardianName;

    protected override void OnStart(string[] args)
    {
        _worker = new ServiceWorker(guardianMode: true);
        _worker.Start();
    }

    protected override void OnStop() => _worker?.Stop();
}

/// <summary>
/// Shared worker used by both services. In guardian mode it just babysits the other
/// service. In blocker mode it runs the whole show: tick the timer, flip the block
/// on/off, and harden/un-harden the services accordingly.
/// </summary>
public sealed class ServiceWorker
{
    private readonly bool _guardian;
    private readonly CancellationTokenSource _cts = new();
    private Thread? _thread;

    // Blocker-mode state:
    private readonly Blocklist _blocklist = new();
    private FilterEngine? _engine;
    private LockState _state = new();
    private bool _blocking;

    // ---- safety: Anchor must never leave the machine unusable ----
    private int _healthFailures;                              // consecutive failed connectivity probes
    private DateTime _nextHealthCheckUtc = DateTime.MinValue;
    private DateTime _failOpenUntilUtc = DateTime.MinValue;   // blocking suspended until this moment
    private int _tripCount;                                   // how often we've had to fail open

    private static readonly TimeSpan HealthCheckEvery = TimeSpan.FromSeconds(30);
    private const int HealthFailuresBeforeTrip = 3;           // ~90 seconds with no connectivity

    public ServiceWorker(bool guardianMode) => _guardian = guardianMode;

    public void Start()
    {
        _thread = new Thread(_guardian ? GuardianLoop : BlockerLoop)
        {
            IsBackground = true,
            Name = _guardian ? "AnchorGuardianLoop" : "AnchorBlockerLoop",
        };
        _thread.Start();
    }

    public void Stop()
    {
        _cts.Cancel();
        _thread?.Join(5000);
        if (_blocking) { try { _engine?.Stop(); } catch { } }
    }

    // ---- Guardian: keep the blocker alive ----
    private void GuardianLoop()
    {
        Log.Info("Guardian started.");
        var token = _cts.Token;
        while (!token.IsCancellationRequested)
        {
            try { ServiceControl.EnsureRunning(AppPaths.ServiceName); }
            catch (Exception ex) { Log.Warn("Guardian check failed: " + ex.Message); }
            token.WaitHandle.WaitOne(3000);
        }
    }

    // ---- Blocker: own the timer and the block ----
    private void BlockerLoop()
    {
        Log.Info("Blocker started.");
        var token = _cts.Token;
        _state = LockState.Load();
        // The engine is created when blocking actually turns on (see ApplyBlockingState),
        // so it always picks up the current DRYRUN setting and starts from clean state.

        var clock = Stopwatch.StartNew();       // monotonic: immune to system-clock changes
        double lastSeconds = 0;

        // We only WRITE the timer to disk/registry when something actually changes, plus a
        // once-a-minute checkpoint while locked (so a reboot loses at most ~1 minute of
        // progress). When idle/unlocked we write nothing at all -- this lets the disk sleep
        // and saves battery, versus the old "save every 5 seconds forever" behavior.
        const double SaveIntervalSeconds = 60;
        double lastSaveSeconds = double.NegativeInfinity;

        while (!token.IsCancellationRequested)
        {
            try
            {
                // 1. How much REAL time passed since the last cycle (never the wall clock).
                double now = clock.Elapsed.TotalSeconds;
                long delta = (long)(now - lastSeconds);
                lastSeconds = now;

                bool changed = false;

                // 2. Adopt a newer/longer lock the GUI may have written since last cycle.
                var disk = LockState.Load();
                if (disk.RemainingSeconds > _state.RemainingSeconds || (disk.IsLocked && !_state.IsLocked))
                {
                    _state = disk;
                    changed = true;
                }

                // 3. Advance the timer by the real elapsed time.
                //    NOTE: the timer keeps running even when the safety checks below have
                //    suspended blocking, so a fault can't be used to stretch a lock out.
                _state.Tick(delta);

                // 4. Decide whether blocking is allowed to be ON right now. The lock says
                //    "should", the safety checks say "may".
                bool shouldBlock = _state.IsLocked && SafetyAllowsBlocking();

                // 5. Turn blocking on or off accordingly (returns true if it flipped).
                if (ApplyBlockingState(shouldBlock)) changed = true;

                // 6. While blocking, keep proving the network still works.
                if (_blocking) CheckNetworkHealth();

                // 5. Persist only when needed, then keep the guardian alive.
                if (changed || (_state.IsLocked && now - lastSaveSeconds >= SaveIntervalSeconds))
                {
                    _state.Save();
                    lastSaveSeconds = now;
                }
                ServiceControl.EnsureRunning(AppPaths.GuardianName);
            }
            catch (Exception ex)
            {
                Log.Error("Blocker loop error: " + ex.Message);
            }

            token.WaitHandle.WaitOne(5000);
        }
    }

    /// <summary>
    /// The safety gate. Blocking stays OFF while the dead-man switch is in its cool-off
    /// window — i.e. we lost general connectivity and backed off automatically.
    ///
    /// There is deliberately NO manual override here. The only escape from an active lock is
    /// Safe Mode (see RECOVERY.md); anything easier would make the commitment meaningless.
    /// The lock timer keeps counting during a cool-off, so a fault can't extend a lock either.
    /// </summary>
    private bool SafetyAllowsBlocking() => DateTime.UtcNow >= _failOpenUntilUtc;

    /// <summary>
    /// Periodically prove that ordinary HTTPS still works while we're filtering. If it stops
    /// working for about a minute and a half, assume Anchor is at fault, switch blocking off,
    /// and back off for a while before trying again. Better a missed block than a dead PC.
    /// </summary>
    private void CheckNetworkHealth()
    {
        var now = DateTime.UtcNow;
        if (now < _nextHealthCheckUtc) return;
        _nextHealthCheckUtc = now + HealthCheckEvery;

        if (NetworkHealth.IsHealthy())
        {
            if (_healthFailures > 0) Log.Info("Network health restored.");
            _healthFailures = 0;
            return;
        }

        _healthFailures++;
        Log.Warn($"Network health probe failed ({_healthFailures}/{HealthFailuresBeforeTrip}).");

        if (_healthFailures < HealthFailuresBeforeTrip) return;

        // Trip: back off longer each time so we can't flap on and off repeatedly.
        _tripCount++;
        var backoff = TimeSpan.FromMinutes(Math.Min(60, 10 * _tripCount));
        _failOpenUntilUtc = now + backoff;
        _healthFailures = 0;
        Log.Error($"No connectivity for ~{HealthCheckEvery.TotalSeconds * HealthFailuresBeforeTrip}s while blocking. " +
                  $"FAILING OPEN for {backoff.TotalMinutes:0} minute(s) as a safety measure. " +
                  "Your lock timer continues to run.");
    }

    /// <summary>Start/stop blocking to match <paramref name="shouldBlock"/>. True if it just flipped.</summary>
    private bool ApplyBlockingState(bool shouldBlock)
    {
        if (shouldBlock && !_blocking)
        {
            // Blocking turns on: start the filter, add the hosts entries, ask browsers to stop
            // using DoH (politely, via policy), and make the services hard to stop.
            // A fresh engine each time picks up the DRYRUN flag and starts with clean state.
            // Observe-only is a property of the LOCK, decided when it started — not something
            // that can be toggled while a lock is running.
            bool dryRun = _state.DryRun;
            _engine = new FilterEngine(_blocklist) { DryRun = dryRun };
            try { _engine.Start(); }
            catch (Exception ex) { Log.Error("Engine failed to start: " + ex.Message); }

            // DRY RUN is strictly OBSERVE-ONLY: we watch traffic and log what we *would*
            // block, but change nothing about the machine — no hosts entries, no browser
            // policy, no service hardening. That makes a trial run completely reversible
            // (and easy to uninstall) while you confirm the filter behaves sensibly.
            if (!dryRun)
            {
                HostsFile.Apply(_blocklist);
                DohPolicy.Disable();
                ServiceControl.Harden();
            }

            _blocking = true;
            Log.Info(dryRun
                ? $"DRY RUN ON — observing only, nothing is dropped or changed. Remaining: {_state.Remaining}."
                : $"Blocking ON. Active time remaining: {_state.Remaining}.");
            return true;
        }

        if (!shouldBlock && _blocking)
        {
            // Blocking turns off — either the lock finished or a safety check tripped.
            // Undo EVERYTHING we changed, in reverse order.
            try { _engine?.Stop(); } catch { }
            HostsFile.Remove();
            DohPolicy.Restore();
            ServiceControl.Unharden();
            _blocking = false;
            Log.Info(_state.IsLocked
                ? "Blocking suspended by a safety check (lock timer still running)."
                : "Blocking OFF. Lock complete.");
            return true;
        }

        return false;
    }
}
