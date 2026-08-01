using System.Runtime.InteropServices;

namespace Anchor;

/// <summary>
/// A thin, hand-written wrapper around WinDivert (https://reqrypt.org/windivert.html),
/// a well-known, Microsoft-signed driver + library that lets a normal (admin) program
/// intercept network packets. We only need five functions, so we declare them here
/// instead of pulling in a third-party NuGet package — that keeps things auditable.
///
/// REQUIREMENT: WinDivert.dll and WinDivert64.sys must sit next to Anchor.exe.
/// build.ps1 downloads them from the official release for you.
///
/// HOW WE USE IT (see FilterEngine): we open a handle with a filter string, then loop:
///   Recv a packet -> look at it -> either Send it back (allow) or drop it (block).
/// Packets we don't Send simply never continue, which is how blocking happens.
/// </summary>
internal static class WinDivert
{
    private const string Dll = "WinDivert.dll";

    // WinDivert layers. LAYER_NETWORK = normal inbound/outbound IP packets (what we want).
    public const int LAYER_NETWORK = 0;

    // Flags for WinDivertOpen. 0 = default (we can read AND re-inject packets).
    public const ulong FLAG_DEFAULT = 0;

    // Returned by WinDivertOpen on failure.
    public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    /// <summary>
    /// WINDIVERT_ADDRESS: 64 bytes of metadata about a packet (direction, interface, etc.).
    /// We never need to interpret it — we just receive it and hand the SAME bytes back on
    /// Send so the packet re-injects correctly. Treating it as an opaque blob is intentional.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = 64)]
    public struct Address
    {
        // 64 opaque bytes. (Explicit Size above guarantees the struct is exactly 64 bytes.)
        private long _a, _b, _c, _d, _e, _f, _g, _h;
    }

    [DllImport(Dll, SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle, byte[] pPacket, uint packetLen, out uint recvLen, ref Address addr);

    [DllImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(
        IntPtr handle, byte[] pPacket, uint packetLen, out uint sendLen, ref Address addr);

    [DllImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertShutdown(IntPtr handle, uint how);

    [DllImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);
}
