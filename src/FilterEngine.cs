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
    private static readonly string[] FilterCandidates =
    {
        "outbound and (" +
        "(tcp.DstPort == 443 and tcp.PayloadLength >= 6 and tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01) or " +
        "(udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xc0 and udp.Payload[0] <= 0xcf) or " +
        "(tcp.DstPort == 53 and tcp.PayloadLength > 0) or " +
        "udp.DstPort == 53)",

        "outbound and (" +
        "(tcp.DstPort == 443 and tcp.PayloadLength > 0) or " +
        "(udp.DstPort == 443) or " +
        "(tcp.DstPort == 53 and tcp.PayloadLength > 0) or " +
        "udp.DstPort == 53)",
    };

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
        if (!_running) return;
        _running = false;

        // Unblock the blocking Recv() call so the loop can exit.
        if (_handle != WinDivert.INVALID_HANDLE_VALUE)
            WinDivert.WinDivertShutdown(_handle, WINDIVERT_SHUTDOWN_RECV);

        _thread?.Join(2000);

        if (_handle != WinDivert.INVALID_HANDLE_VALUE)
        {
            WinDivert.WinDivertClose(_handle);
            _handle = WinDivert.INVALID_HANDLE_VALUE;
        }
        Log.Info($"Filter engine stopped. Blocked {BlockedCount} connection attempt(s) this run.");
    }

    private void Loop()
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
                if (PacketParser.TryGetHost(packet.AsSpan(0, (int)len), out string host)
                    && _blocklist.IsBlocked(host))
                {
                    block = true;
                    Interlocked.Increment(ref _blockedCount);
                    Log.Info($"Blocked {host}");
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
}
