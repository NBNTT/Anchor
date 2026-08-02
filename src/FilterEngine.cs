using System.Runtime.InteropServices;

namespace Anchor;

/// <summary>
/// The actual blocker. It runs on its own thread and does the classic WinDivert loop:
///
///     receive a packet  ->  is it heading to a blocked site?  ->  yes: drop it
///                                                              ->  no:  send it on
///
/// Because this works at the network layer (below the apps), it blocks EVERY browser
/// and EVERY desktop app at once. The apps just see their connections fail.
///
/// We only look at:
///   - outbound TLS ClientHello packets on port 443 (to read the SNI hostname), and
///   - outbound DNS queries on port 53 (belt-and-suspenders).
/// Everything else is passed straight through untouched.
/// </summary>
public sealed class FilterEngine
{
    // We want to touch as FEW packets as possible, for CPU/battery reasons. WinDivert only
    // hands us packets that match one of these filters; everything else flows by untouched.
    //
    // PREFERRED filter: divert ONLY the handshake packets that carry the site name:
    //   TCP 443 -> TLS ClientHello (record byte 0 == 0x16, handshake byte 5 == 0x01)
    //   UDP 443 -> QUIC v1 Initial (long-header first byte 0xC0-0xCF, client Initials padded >= 1200)
    //   port 53 -> DNS queries
    // Bulk uploads/downloads and established QUIC data are NEVER copied into our process.
    //
    // FALLBACK filter: if a WinDivert build doesn't support payload-byte indexing in filters,
    // WinDivertOpen rejects the preferred filter and we fall back to the broader one (still
    // correct, just inspects more packets). Blocking never silently breaks.
    // IMPORTANT (fixed 2026-08-01): we used to divert ONLY the first TLS packet, matching
    // "record 0x16 + handshake 0x01". That silently stopped working, because Chrome's
    // post-quantum key exchange makes the ClientHello ~2 KB — bigger than one TCP segment.
    // The site name then sits in the SECOND segment, which that filter never delivered, so
    // browser traffic sailed straight through. We now divert all outbound TCP 443 payload
    // packets and stitch the handshake together in user space (see HandleTcp443 below).
    //
    // The cost is that busy uploads pass through our loop again; the fast path for a packet
    // that isn't part of a pending handshake is a single dictionary lookup, then forward.
    //
    // Client QUIC Initial packets are always padded to >= 1200 bytes (RFC 9000 s14.1), so the
    // UDP test still catches every one of them, including continuation Initials.
    private static readonly string[] FilterCandidates =
    {
        "outbound and (" +
        "(tcp.DstPort == 443 and tcp.PayloadLength > 0) or " +
        "(udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xc0 and udp.Payload[0] <= 0xcf) or " +
        "(tcp.DstPort == 53 and tcp.PayloadLength > 0) or " +
        "udp.DstPort == 53)",

        "outbound and (" +
        "(tcp.DstPort == 443 and tcp.PayloadLength > 0) or " +
        "(udp.DstPort == 443) or " +
        "(tcp.DstPort == 53 and tcp.PayloadLength > 0) or " +
        "udp.DstPort == 53)",
    };

    // ---- TLS handshake reassembly (for ClientHellos split across packets) ----
    private const int MaxHandshakeBytes = 16384;   // a ClientHello never legitimately exceeds this
    private const int MaxPendingFlows = 1024;      // hard cap so a flood can't grow memory
    private static readonly TimeSpan PendingTtl = TimeSpan.FromSeconds(10);

    private sealed class PendingHandshake
    {
        public byte[] Buffer = new byte[4096];
        public int Length;
        public DateTime FirstSeenUtc;
    }

    private readonly Dictionary<ulong, PendingHandshake> _pending = new();
    private DateTime _lastSweepUtc = DateTime.UtcNow;

    // ---- log throttling ----
    // A blocked site makes browsers retry hard. Writing a log line per dropped packet meant
    // hundreds of synchronous disk writes a second, which stalls this loop — and a stalled
    // loop with a broad filter means packets pile up and get dropped. So we log at most one
    // line per hostname per interval and count the rest.
    private static readonly TimeSpan LogInterval = TimeSpan.FromSeconds(30);
    private readonly Dictionary<string, (DateTime LastLogged, int Suppressed)> _logState = new();

    /// <summary>
    /// DRY RUN: if C:\ProgramData\Anchor\DRYRUN exists, we log what we WOULD block but drop
    /// nothing. Use this to validate a filter change safely before letting it enforce.
    /// </summary>
    public bool DryRun { get; init; }

    private const uint WINDIVERT_SHUTDOWN_RECV = 0x1;
    private const int ERROR_NO_DATA = 232;   // returned by Recv after we shut the handle down

    private readonly Blocklist _blocklist;
    private IntPtr _handle = WinDivert.INVALID_HANDLE_VALUE;
    private Thread? _thread;
    private volatile bool _running;
    private long _blockedCount;

    public FilterEngine(Blocklist blocklist) => _blocklist = blocklist;

    public bool IsRunning => _running;
    public long BlockedCount => Interlocked.Read(ref _blockedCount);

    /// <summary>Open the driver and start the loop. Throws if WinDivert can't open (see message).</summary>
    public void Start()
    {
        if (_running) return;

        _handle = OpenWithFallback();
        if (_handle == WinDivert.INVALID_HANDLE_VALUE)
        {
            int err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"Could not start the network filter (WinDivertOpen failed, error {err}). " +
                "Make sure WinDivert.dll and WinDivert64.sys are next to Anchor.exe and you are running as administrator.");
        }

        _running = true;
        _thread = new Thread(Loop) { IsBackground = true, Name = "AnchorFilter" };
        _thread.Start();
        Log.Info("Filter engine started.");
    }

    /// <summary>Try each filter in order; use the first one WinDivert accepts (preferred = low power).</summary>
    private static IntPtr OpenWithFallback()
    {
        for (int i = 0; i < FilterCandidates.Length; i++)
        {
            IntPtr h = WinDivert.WinDivertOpen(FilterCandidates[i], WinDivert.LAYER_NETWORK, 0, WinDivert.FLAG_DEFAULT);
            if (h != WinDivert.INVALID_HANDLE_VALUE)
            {
                Log.Info($"Network filter opened using candidate #{i + 1} " +
                         $"({(i == 0 ? "ClientHello-only, low power" : "broad fallback")}).");
                return h;
            }
            Log.Warn($"Filter candidate #{i + 1} not accepted (error {Marshal.GetLastWin32Error()}); trying next.");
        }
        return WinDivert.INVALID_HANDLE_VALUE;
    }

    /// <summary>Stop the loop and close the driver handle.</summary>
    public void Stop()
    {
        _running = false;

        // Unblock the blocking Recv() call so the loop can exit. The loop's finally block is
        // what actually closes the handle (so a crash can't leave packets blackholed), and it
        // may already have run — a shutdown on a closed handle simply fails, which is fine.
        var h = _handle;
        if (h != WinDivert.INVALID_HANDLE_VALUE)
        {
            try { WinDivert.WinDivertShutdown(h, WINDIVERT_SHUTDOWN_RECV); } catch { }
        }

        _thread?.Join(3000);

        // Belt and braces: if the thread never ran or already exited, make sure it's closed.
        h = _handle;
        _handle = WinDivert.INVALID_HANDLE_VALUE;
        if (h != WinDivert.INVALID_HANDLE_VALUE)
        {
            try { WinDivert.WinDivertClose(h); } catch { }
        }
        Log.Info($"Filter engine stopped. Blocked {BlockedCount} connection attempt(s) this run.");
    }

    /// <summary>
    /// Record a block, but only write to disk occasionally per hostname (see LogInterval).
    /// Returns true if the packet should actually be dropped (false in dry-run mode).
    /// </summary>
    private bool NoteBlock(string host)
    {
        Interlocked.Increment(ref _blockedCount);

        var now = DateTime.UtcNow;
        _logState.TryGetValue(host, out var st);
        if (now - st.LastLogged >= LogInterval)
        {
            string extra = st.Suppressed > 0 ? $" (+{st.Suppressed} more since last note)" : "";
            Log.Info($"{(DryRun ? "[DRY RUN] would block" : "Blocked")} {host}{extra}");
            _logState[host] = (now, 0);
        }
        else
        {
            _logState[host] = (st.LastLogged, st.Suppressed + 1);
        }

        return !DryRun;
    }

    private void Loop()
    {
        // SAFETY: whatever happens in here — an exception, a shutdown, a bug — we MUST close
        // the WinDivert handle on the way out. A live handle with no one reading it silently
        // swallows every matching packet, which with a broad filter means the machine loses
        // all HTTPS. Failing OPEN is always better than failing closed.
        try
        {
            PumpPackets();
        }
        catch (Exception ex)
        {
            Log.Error("Filter loop crashed; failing open so traffic keeps flowing: " + ex.Message);
        }
        finally
        {
            _running = false;
            var h = _handle;
            _handle = WinDivert.INVALID_HANDLE_VALUE;
            if (h != WinDivert.INVALID_HANDLE_VALUE)
            {
                try { WinDivert.WinDivertClose(h); } catch { }
            }
        }
    }

    private void PumpPackets()
    {
        // 65535 = max IP packet size, so one buffer always holds a full packet.
        var packet = new byte[65535];
        var addr = new WinDivert.Address();

        while (_running)
        {
            if (!WinDivert.WinDivertRecv(_handle, packet, (uint)packet.Length, out uint len, ref addr))
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_NO_DATA) break;         // we were shut down: exit cleanly
                continue;                                 // transient hiccup: try the next packet
            }

            bool block = false;
            try
            {
                var span = packet.AsSpan(0, (int)len);

                // Outbound TCP 443 goes through the reassembler, so a ClientHello spread over
                // several segments is still matched. Everything else (DNS, QUIC) is self-contained.
                if (PacketParser.TryGetTcpFlow(span, out ulong flowKey, out int pStart, out int pLen, out int dstPort)
                    && dstPort == 443 && pLen > 0)
                {
                    block = HandleTcp443(flowKey, span.Slice(pStart, pLen));
                }
                else if (PacketParser.TryGetHost(span, out string host) && _blocklist.IsBlocked(host))
                {
                    block = NoteBlock(host);
                }
            }
            catch
            {
                // If parsing ever throws, fail OPEN (allow) — a blocker bug must never break the whole network.
                block = false;
            }

            if (block)
            {
                // Do nothing: not re-sending the packet is what drops the connection.
                continue;
            }

            // Allowed: put the packet back on the wire exactly as we got it.
            WinDivert.WinDivertSend(_handle, packet, len, out _, ref addr);
        }
    }

    /// <summary>
    /// Decide whether to drop an outbound TCP-443 packet, stitching together a TLS ClientHello
    /// that may be spread over several segments.
    ///
    /// Returns true to DROP. Dropping any single segment of a handshake is enough to kill the
    /// connection, because the server never receives a complete ClientHello — so it's fine that
    /// earlier segments were already forwarded before we could read the name.
    /// </summary>
    internal bool HandleTcp443(ulong flowKey, ReadOnlySpan<byte> payload)
    {
        SweepExpired();

        bool startsHandshake = payload.Length >= 6 && payload[0] == 0x16 && payload[5] == 0x01;

        if (startsHandshake)
        {
            if (_pending.Count >= MaxPendingFlows) return false;   // overloaded: fail open
            var fresh = new PendingHandshake { FirstSeenUtc = DateTime.UtcNow };
            _pending[flowKey] = fresh;
            Append(fresh, payload);
        }
        else if (_pending.TryGetValue(flowKey, out var existing))
        {
            Append(existing, payload);                              // continuation of a ClientHello
        }
        else
        {
            return false;   // FAST PATH: ordinary data on an established connection — pass it on.
        }

        var pending = _pending[flowKey];

        // Skip the 5-byte TLS record header, then try to read the server name.
        string? sni = pending.Length > 5
            ? PacketParser.ParseSniFromHandshake(pending.Buffer.AsSpan(5, pending.Length - 5))
            : null;

        if (sni != null)
        {
            _pending.Remove(flowKey);                               // decided, stop buffering
            if (_blocklist.IsBlocked(sni)) return NoteBlock(sni);
            return false;
        }

        // Couldn't read a name yet. Keep buffering unless this has grown unreasonable.
        if (pending.Length >= MaxHandshakeBytes) _pending.Remove(flowKey);
        return false;
    }

    private static void Append(PendingHandshake p, ReadOnlySpan<byte> data)
    {
        int needed = p.Length + data.Length;
        if (needed > MaxHandshakeBytes) needed = MaxHandshakeBytes;
        if (needed > p.Buffer.Length)
        {
            int size = p.Buffer.Length;
            while (size < needed) size *= 2;
            Array.Resize(ref p.Buffer, Math.Min(size, MaxHandshakeBytes));
        }
        int room = p.Buffer.Length - p.Length;
        int take = Math.Min(room, data.Length);
        if (take > 0)
        {
            data[..take].CopyTo(p.Buffer.AsSpan(p.Length));
            p.Length += take;
        }
    }

    /// <summary>Drop half-finished handshakes that never completed, so the table can't grow forever.</summary>
    private void SweepExpired()
    {
        var now = DateTime.UtcNow;
        if (now - _lastSweepUtc < TimeSpan.FromSeconds(5)) return;
        _lastSweepUtc = now;

        if (_pending.Count == 0) return;
        var stale = _pending.Where(kv => now - kv.Value.FirstSeenUtc > PendingTtl)
                            .Select(kv => kv.Key).ToList();
        foreach (var k in stale) _pending.Remove(k);
    }
}
