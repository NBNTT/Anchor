using System.Security.Cryptography;

namespace Anchor;

/// <summary>
/// Reads the site name (SNI) out of a QUIC "Initial" packet — the UDP/HTTP-3 equivalent of
/// the TLS ClientHello we read on TCP. This is what lets Anchor block YouTube/Reddit over
/// QUIC (which Chrome and Google use heavily), not just over ordinary TCP HTTPS.
///
/// Why it's more work than TCP: in QUIC the ClientHello is ENCRYPTED. But the encryption keys
/// for the Initial packet are derived from a fixed public salt plus the connection ID that's
/// right there in the packet — so anyone (including us) can decrypt it. We follow RFC 9001:
///   1. derive the client Initial keys from the Destination Connection ID,
///   2. remove "header protection" to read the packet number,
///   3. AES-GCM-decrypt the payload,
///   4. pull the ClientHello out of the CRYPTO frames and read its SNI.
///
/// Everything is best-effort and fail-safe: ANY problem (unsupported version, GCM auth
/// failure, malformed frame) just returns false = "couldn't read it" = allow. We never
/// break a connection we don't understand.
///
/// Scope: QUIC version 1 (RFC 9000/9001), which is what real browsers use today. Other
/// versions (e.g. the rarely-deployed v2) return false. See README for that caveat.
/// </summary>
public static class QuicParser
{
    private const uint QuicV1 = 0x00000001;

    /// <summary>Try to read the SNI from a QUIC Initial packet. Returns false on anything unexpected.</summary>
    public static bool TryGetInitialSni(ReadOnlySpan<byte> pkt, out string host)
    {
        host = string.Empty;
        try
        {
            return TryParse(pkt, out host);
        }
        catch
        {
            // Crypto/format error -> treat as "not readable" -> allow.
            host = string.Empty;
            return false;
        }
    }

    private static bool TryParse(ReadOnlySpan<byte> pkt, out string host)
    {
        host = string.Empty;
        if (pkt.Length < 7) return false;

        byte first = pkt[0];
        if ((first & 0x80) == 0) return false;          // must be a long header
        if ((first & 0x40) == 0) return false;          // fixed bit must be 1
        if ((first & 0x30) != 0x00) return false;       // packet type must be Initial (00)

        uint version = (uint)((pkt[1] << 24) | (pkt[2] << 16) | (pkt[3] << 8) | pkt[4]);
        if (version != QuicV1) return false;            // only QUIC v1

        int p = 5;
        int dcidLen = pkt[p++]; if (dcidLen > 20 || p + dcidLen > pkt.Length) return false;
        byte[] dcid = pkt.Slice(p, dcidLen).ToArray(); p += dcidLen;

        int scidLen = pkt[p++]; if (p + scidLen > pkt.Length) return false;
        p += scidLen;

        if (!TryReadVarint(pkt, ref p, out ulong tokenLen)) return false;
        p += (int)tokenLen; if (p > pkt.Length) return false;

        if (!TryReadVarint(pkt, ref p, out ulong length)) return false;
        int pnOffset = p;
        if (pnOffset + (int)length > pkt.Length) return false;

        // Derive the client Initial keys from the Destination Connection ID.
        DeriveClientInitialKeys(dcid, out byte[] key, out byte[] iv, out byte[] hp);

        // --- remove header protection (RFC 9001 §5.4) ---
        int sampleOffset = pnOffset + 4;               // sample starts 4 bytes into the (assumed) pn area
        if (sampleOffset + 16 > pkt.Length) return false;
        byte[] mask = AesEcbBlock(hp, pkt.Slice(sampleOffset, 16).ToArray());

        byte firstUnmasked = (byte)(first ^ (mask[0] & 0x0f));
        int pnLen = (firstUnmasked & 0x03) + 1;

        // Rebuild the header bytes (the AEAD "associated data") with the unmasked first byte + pn.
        byte[] header = pkt.Slice(0, pnOffset + pnLen).ToArray();
        header[0] = firstUnmasked;
        long packetNumber = 0;
        for (int i = 0; i < pnLen; i++)
        {
            byte b = (byte)(pkt[pnOffset + i] ^ mask[1 + i]);
            header[pnOffset + i] = b;
            packetNumber = (packetNumber << 8) | b;
        }

        // nonce = iv XOR (packet number, left-padded to 12 bytes).
        byte[] nonce = new byte[12];
        for (int i = 0; i < 8; i++) nonce[11 - i] = (byte)((packetNumber >> (8 * i)) & 0xff);
        for (int i = 0; i < 12; i++) nonce[i] ^= iv[i];

        // --- AES-128-GCM decrypt the payload ---
        int payloadOffset = pnOffset + pnLen;
        int payloadLen = (int)length - pnLen;
        if (payloadLen < 16 || payloadOffset + payloadLen > pkt.Length) return false;

        byte[] cipher = pkt.Slice(payloadOffset, payloadLen - 16).ToArray();
        byte[] tag = pkt.Slice(payloadOffset + payloadLen - 16, 16).ToArray();
        byte[] plain = new byte[cipher.Length];

        using (var gcm = new AesGcm(key, 16))
        {
            gcm.Decrypt(nonce, cipher, tag, plain, header);   // throws if authentication fails
        }

        // --- pull the ClientHello out of the CRYPTO frames and read its SNI ---
        byte[]? clientHello = ReassembleCryptoFromZero(plain);
        if (clientHello == null) return false;

        var sni = PacketParser.ParseSniFromHandshake(clientHello);
        if (sni == null) return false;
        host = sni;
        return true;
    }

    /// <summary>
    /// RFC 9001 §5.2 key derivation. Exposed internally so a test can verify it against the
    /// published RFC vectors (this is the part most worth double-checking).
    /// </summary>
    internal static void DeriveClientInitialKeys(byte[] dcid, out byte[] key, out byte[] iv, out byte[] hp)
    {
        byte[] initialSecret = HKDF.Extract(HashAlgorithmName.SHA256, dcid, RealInitialSalt);
        byte[] client = ExpandLabel(initialSecret, "client in", 32);
        key = ExpandLabel(client, "quic key", 16);
        iv = ExpandLabel(client, "quic iv", 12);
        hp = ExpandLabel(client, "quic hp", 16);
    }

    // RFC 9001 §5.2 — the fixed public salt used to derive QUIC v1 Initial keys.
    private static readonly byte[] RealInitialSalt =
    {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    };

    /// <summary>HKDF-Expand-Label from TLS 1.3 (RFC 8446 §7.1), as QUIC uses it.</summary>
    private static byte[] ExpandLabel(byte[] secret, string label, int length)
    {
        string full = "tls13 " + label;
        byte[] lbl = System.Text.Encoding.ASCII.GetBytes(full);

        // info = uint16 length | uint8 labelLen | label | uint8 contextLen(0)
        byte[] info = new byte[2 + 1 + lbl.Length + 1];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)lbl.Length;
        Array.Copy(lbl, 0, info, 3, lbl.Length);
        info[^1] = 0;

        return HKDF.Expand(HashAlgorithmName.SHA256, secret, length, info);
    }

    /// <summary>Encrypt a single 16-byte block with AES-ECB (used for QUIC header protection).</summary>
    private static byte[] AesEcbBlock(byte[] hpKey, byte[] sample)
    {
        using var aes = Aes.Create();
        aes.Key = hpKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(sample, 0, 16);
    }

    /// <summary>
    /// Walk the decrypted QUIC frames and stitch together the CRYPTO data starting at offset 0
    /// (that's where the ClientHello begins). Returns null if there's no CRYPTO data at offset 0.
    /// </summary>
    private static byte[]? ReassembleCryptoFromZero(ReadOnlySpan<byte> frames)
    {
        var chunks = new SortedDictionary<ulong, byte[]>();
        int p = 0;

        while (p < frames.Length)
        {
            if (!TryReadVarint(frames, ref p, out ulong type)) break;

            if (type == 0x00 || type == 0x01) continue;   // PADDING / PING: no body
            if (type == 0x06)                              // CRYPTO
            {
                if (!TryReadVarint(frames, ref p, out ulong offset)) break;
                if (!TryReadVarint(frames, ref p, out ulong len)) break;
                if (p + (int)len > frames.Length) break;
                chunks[offset] = frames.Slice(p, (int)len).ToArray();
                p += (int)len;
                continue;
            }

            // Any other frame type (e.g. ACK): stop — we've usually already got the ClientHello.
            break;
        }

        if (!chunks.TryGetValue(0, out _)) return null;

        // Concatenate contiguous chunks starting at offset 0.
        using var ms = new MemoryStream();
        ulong next = 0;
        foreach (var kv in chunks)
        {
            if (kv.Key != next) break;       // gap: stop (we only handle a contiguous run)
            ms.Write(kv.Value, 0, kv.Value.Length);
            next += (ulong)kv.Value.Length;
        }
        return ms.ToArray();
    }

    /// <summary>Read a QUIC variable-length integer (RFC 9000 §16). Advances <paramref name="p"/>.</summary>
    private static bool TryReadVarint(ReadOnlySpan<byte> b, ref int p, out ulong value)
    {
        value = 0;
        if (p >= b.Length) return false;
        int len = 1 << (b[p] >> 6);                 // top 2 bits pick 1/2/4/8 bytes
        if (p + len > b.Length) return false;

        ulong v = (ulong)(b[p] & 0x3f);
        for (int i = 1; i < len; i++) v = (v << 8) | b[p + i];
        p += len;
        value = v;
        return true;
    }
}
