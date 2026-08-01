using System.Diagnostics;
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
        _engine = new FilterEngine(_blocklist);

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
                _state.Tick(delta);

                // 4. Turn blocking on or off to match the timer (returns true if it flipped).
                if (ApplyBlockingState()) changed = true;

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

    /// <summary>Start/stop blocking to match the timer. Returns true if the state just flipped.</summary>
    private bool ApplyBlockingState()
    {
        if (_state.IsLocked && !_blocking)
        {
            // Lock just became active -> start blocking + make ourselves hard to remove.
            try { _engine!.Start(); }
            catch (Exception ex) { Log.Error("Engine failed to start (hosts-file layer still active): " + ex.Message); }
            HostsFile.Apply(_blocklist);
            ServiceControl.Harden();
            _blocking = true;
            Log.Info($"Blocking ON. Active time remaining: {_state.Remaining}.");
            return true;
        }

        if (!_state.IsLocked && _blocking)
        {
            // Lock finished -> stop blocking + restore normal permissions so you can uninstall.
            try { _engine!.Stop(); } catch { }
            HostsFile.Remove();
            ServiceControl.Unharden();
            _blocking = false;
            Log.Info("Blocking OFF. Lock complete.");
            return true;
        }

        return false;
    }
}
