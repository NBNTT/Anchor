using System.Net.Security;
using System.Net.Sockets;

namespace Anchor;

/// <summary>
/// Answers one question: "is normal HTTPS still working on this machine?"
///
/// This is Anchor's dead-man switch. If our filter ever breaks general connectivity — a bug,
/// a crash, a stalled packet loop, a rule that matches far more than intended — the service
/// notices and turns blocking OFF rather than leaving you with a dead network.
///
/// The check deliberately does a REAL TLS handshake to a well-known IP address:
///   - Using an IP means it doesn't depend on DNS, so it still works if name resolution is
///     the thing that's broken.
///   - Doing a full handshake means the ClientHello travels through our own filter, so the
///     check exercises exactly the path most likely to break.
///   - The hosts used are neutral infrastructure, never anything on the blocklist.
/// </summary>
public static class NetworkHealth
{
    // (address, name to present in the TLS handshake). Several, so one provider being down
    // doesn't look like a machine-wide outage.
    private static readonly (string Ip, string Host)[] Probes =
    {
        ("1.1.1.1", "one.one.one.one"),
        ("8.8.8.8", "dns.google"),
        ("9.9.9.9", "dns.quad9.net"),
    };

    private const int TimeoutMs = 4000;

    /// <summary>True if at least one probe completes a TLS handshake. Never throws.</summary>
    public static bool IsHealthy()
    {
        foreach (var probe in Probes)
        {
            if (TryProbe(probe.Ip, probe.Host)) return true;
        }
        return false;
    }

    private static bool TryProbe(string ip, string host)
    {
        try
        {
            using var client = new TcpClient();
            if (!client.ConnectAsync(ip, 443).Wait(TimeoutMs)) return false;

            using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
                // We only care that the handshake completes end to end, not who the cert
                // belongs to — this is a connectivity probe, not a security decision.
                userCertificateValidationCallback: (_, _, _, _) => true);

            return ssl.AuthenticateAsClientAsync(host).Wait(TimeoutMs);
        }
        catch
        {
            return false;   // any failure counts as "this probe didn't work"
        }
    }
}
