using System.Text;

namespace Anchor;

/// <summary>
/// Reads a raw network packet and pulls out the hostname it is trying to reach,
/// from one of two places:
///   1. The TLS "ClientHello" on port 443 -> the SNI field (the server name,
///      sent in the clear even when the browser uses encrypted DNS / DoH).
///   2. A plain DNS query on port 53 -> the domain being looked up.
///
/// This class is PURE and defensive: it only ever returns a hostname when it is
/// completely sure it parsed one. Any malformed/partial packet returns false, so
/// the engine's rule stays simple: "block only on a confident hostname match."
///
/// Everything is bounds-checked. We never read past the packet buffer.
/// </summary>
public static class PacketParser
{
    // IP protocol numbers.
    private const byte ProtoTcp = 6;
    private const byte ProtoUdp = 17;

    /// <summary>
    /// Given a full IP packet, try to find the hostname it targets (SNI on 443, or DNS name on 53).
    /// Returns true and sets <paramref name="host"/> only on success.
    /// </summary>
    public static bool TryGetHost(ReadOnlySpan<byte> packet, out string host)
    {
        host = string.Empty;
        if (packet.Length < 20) return false;

        int version = packet[0] >> 4;
        int l4Start;      // where the TCP/UDP header begins
        byte protocol;

        if (version == 4)
        {
            int ihl = (packet[0] & 0x0F) * 4;          // IPv4 header length in bytes
            if (ihl < 20 || packet.Length < ihl) return false;
            protocol = packet[9];
            l4Start = ihl;
        }
        else if (version == 6)
        {
            if (packet.Length < 40) return false;
            protocol = packet[6];                       // "next header"; we ignore IPv6 extension headers (rare here)
            l4Start = 40;
        }
        else
        {
            return false;
        }

        if (protocol == ProtoTcp)
        {
            if (packet.Length < l4Start + 20) return false;
            int dstPort = (packet[l4Start + 2] << 8) | packet[l4Start + 3];
            int tcpHeaderLen = (packet[l4Start + 12] >> 4) * 4;
            int payloadStart = l4Start + tcpHeaderLen;
            if (tcpHeaderLen < 20 || payloadStart > packet.Length) return false;

            ReadOnlySpan<byte> payload = packet[payloadStart..];
            if (payload.Length == 0) return false;

            if (dstPort == 443)
            {
                var sni = ParseTlsSni(payload);
                if (sni != null) { host = sni; return true; }
            }
            else if (dstPort == 53)
            {
                // DNS-over-TCP prefixes the message with a 2-byte length. Skip it.
                if (payload.Length < 2) return false;
                var name = ParseDnsQuestion(payload[2..]);
                if (name != null) { host = name; return true; }
            }
        }
        else if (protocol == ProtoUdp)
        {
            if (packet.Length < l4Start + 8) return false;
            int dstPort = (packet[l4Start + 2] << 8) | packet[l4Start + 3];
            ReadOnlySpan<byte> payload = packet[(l4Start + 8)..];

            if (dstPort == 53)
            {
                var name = ParseDnsQuestion(payload);
                if (name != null) { host = name; return true; }
            }
            else if (dstPort == 443)
            {
                // QUIC / HTTP-3 runs over UDP 443. The site name is inside the (encrypted)
                // QUIC Initial packet; QuicParser decrypts it to read the SNI.
                if (QuicParser.TryGetInitialSni(payload, out var name) && name.Length > 0)
                {
                    host = name;
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Extract the SNI from a TLS record that wraps a ClientHello (the TCP/HTTPS case,
    /// where the bytes start with a 0x16 "handshake" record header). Strips the 5-byte
    /// record header and hands the rest to the shared ClientHello parser.
    /// </summary>
    private static string? ParseTlsSni(ReadOnlySpan<byte> d)
    {
        // TLS record header: type(1)=0x16 handshake, version(2), length(2).
        if (d.Length < 5 || d[0] != 0x16) return null;
        return ParseSniFromHandshake(d[5..]);
    }

    /// <summary>
    /// Extract the SNI hostname from a raw TLS ClientHello handshake message (starts with
    /// 0x01). This is shared by TCP (after stripping the record header) and QUIC (where the
    /// ClientHello lives inside a CRYPTO frame with no record header). Returns null if this
    /// isn't a ClientHello or the name isn't present/complete in the given bytes.
    /// </summary>
    internal static string? ParseSniFromHandshake(ReadOnlySpan<byte> d)
    {
        int p = 0;

        // Handshake header: type(1)=0x01 ClientHello, length(3).
        if (d.Length < p + 4 || d[p] != 0x01) return null;
        p += 4;

        // client_version(2) + random(32)
        p += 2 + 32;
        if (d.Length < p + 1) return null;

        // session_id: length(1) + bytes
        int sidLen = d[p]; p += 1 + sidLen;
        if (d.Length < p + 2) return null;

        // cipher_suites: length(2) + bytes
        int csLen = (d[p] << 8) | d[p + 1]; p += 2 + csLen;
        if (d.Length < p + 1) return null;

        // compression_methods: length(1) + bytes
        int compLen = d[p]; p += 1 + compLen;
        if (d.Length < p + 2) return null;

        // extensions: total length(2) + the extensions themselves
        int extTotal = (d[p] << 8) | d[p + 1]; p += 2;
        int extEnd = Math.Min(p + extTotal, d.Length);

        while (p + 4 <= extEnd)
        {
            int extType = (d[p] << 8) | d[p + 1];
            int extLen = (d[p + 2] << 8) | d[p + 3];
            p += 4;
            if (p + extLen > d.Length) return null;

            if (extType == 0x0000) // server_name extension
            {
                int q = p;
                if (q + 2 > d.Length) return null;
                q += 2;                                  // server_name_list length (skip)
                if (q + 3 > d.Length) return null;
                int nameType = d[q]; q += 1;             // 0 = host_name
                int nameLen = (d[q] << 8) | d[q + 1]; q += 2;
                if (nameType != 0 || q + nameLen > d.Length) return null;
                return Encoding.ASCII.GetString(d.Slice(q, nameLen));
            }

            p += extLen;
        }

        return null;
    }

    /// <summary>
    /// Extract the first question name from a DNS message (the domain being looked up).
    /// Returns null on any malformed input.
    /// </summary>
    private static string? ParseDnsQuestion(ReadOnlySpan<byte> dns)
    {
        if (dns.Length < 12) return null;
        int questionCount = (dns[4] << 8) | dns[5];
        if (questionCount < 1) return null;

        int p = 12; // DNS questions start right after the 12-byte header
        var sb = new StringBuilder(64);

        while (true)
        {
            if (p >= dns.Length) return null;
            int len = dns[p]; p++;

            if (len == 0) break;                         // end of name
            if ((len & 0xC0) != 0) return null;          // compression pointer: not expected in a question, bail
            if (p + len > dns.Length) return null;

            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(dns.Slice(p, len)));
            p += len;
        }

        return sb.Length == 0 ? null : sb.ToString();
    }
}
