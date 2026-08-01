namespace Anchor;

/// <summary>
/// The list of domains to block, plus the matching rule. This class is PURE:
/// it does no networking and touches no files, so you can unit-test it easily
/// (feed it a hostname, get true/false). This is the heart of "what gets blocked".
///
/// HOW MATCHING WORKS:
///   A hostname is blocked if it equals a listed domain OR ends with "." + that domain.
///   So listing "youtube.com" also blocks "m.youtube.com" and "www.youtube.com",
///   but NOT "notyoutube.com" (that would need to end in ".youtube.com").
///
///   This is why "youtubei.googleapis.com" can be listed WITHOUT blocking the rest
///   of googleapis.com: we only match that exact host and its subdomains.
/// </summary>
public sealed class Blocklist
{
    // Edit this list to change what Anchor blocks. Keep entries lowercase, no "www.".
    private static readonly string[] DefaultDomains =
    {
        // ---- YouTube ----
        "youtube.com",              // main site (covers www / m / music.youtube.com)
        "youtu.be",                 // short share links
        "youtube-nocookie.com",     // privacy-embed domain
        "youtubei.googleapis.com",  // the API the site + apps call for video data (NOT all of googleapis.com)
        "googlevideo.com",          // the actual video stream CDN (kills playback even if a page slips through)
        "ytimg.com",                // youtube image/thumbnail CDN

        // ---- Reddit ----
        "reddit.com",               // main site (covers www / old / new / np / oauth / gateway.reddit.com)
        "redd.it",                  // link shortener + i.redd.it / v.redd.it media
        "redditstatic.com",         // reddit's static assets
        "redditmedia.com",          // reddit's media CDN
    };

    private readonly HashSet<string> _domains;

    public Blocklist() : this(DefaultDomains) { }

    /// <summary>Construct from a custom list (used by tests, or a future editable-file feature).</summary>
    public Blocklist(IEnumerable<string> domains)
    {
        _domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in domains)
        {
            var clean = Normalize(d);
            if (clean.Length > 0) _domains.Add(clean);
        }
    }

    /// <summary>The domains this blocklist covers (for showing in the GUI / hosts file).</summary>
    public IReadOnlyCollection<string> Domains => _domains;

    /// <summary>
    /// The one question that matters: should we block a connection to this hostname?
    /// Returns false for null/empty so anything we FAIL to parse is allowed through
    /// (we only ever block on a positive, confident match).
    /// </summary>
    public bool IsBlocked(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        host = Normalize(host);

        foreach (var domain in _domains)
        {
            if (host.Equals(domain, StringComparison.OrdinalIgnoreCase)) return true;
            if (host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>Trim, drop a trailing dot, and strip a leading "www." so the list is tidy.</summary>
    private static string Normalize(string host)
    {
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        return host;
    }
}
