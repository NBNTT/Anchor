using System.IO;
using System.Text;

namespace Anchor;

/// <summary>
/// The secondary, "belt-and-suspenders" block layer: it points the blocked domains
/// at 0.0.0.0 in the Windows hosts file. This alone is easy for a browser to bypass
/// (that's why the WinDivert FilterEngine is the real defense), but it's a cheap extra
/// layer that catches simpler apps and makes the block obvious.
///
/// We write our entries between two marker lines so we can cleanly remove ONLY our
/// entries later, never touching anything else in the user's hosts file.
/// </summary>
public static class HostsFile
{
    private const string StartMarker = "# ANCHOR-START (managed by Anchor - do not edit this block)";
    private const string EndMarker = "# ANCHOR-END";

    /// <summary>Add (or refresh) our block entries for every domain in the blocklist.</summary>
    public static void Apply(Blocklist blocklist)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine(StartMarker);
            foreach (var domain in blocklist.Domains)
            {
                // Block the bare domain and the common "www." form. (The FilterEngine is what
                // catches every other subdomain; these lines are just the easy wins.)
                sb.AppendLine($"0.0.0.0 {domain}");
                sb.AppendLine($"0.0.0.0 www.{domain}");
            }
            sb.AppendLine(EndMarker);

            string existing = File.Exists(AppPaths.HostsFile) ? File.ReadAllText(AppPaths.HostsFile) : "";
            string cleaned = StripOurBlock(existing).TrimEnd();
            string updated = cleaned.Length == 0
                ? sb.ToString()
                : cleaned + Environment.NewLine + Environment.NewLine + sb;

            File.WriteAllText(AppPaths.HostsFile, updated);
            Log.Info("Hosts file entries applied.");
        }
        catch (Exception ex)
        {
            // Non-fatal: the FilterEngine is the primary block. Just note it.
            Log.Warn("Could not update hosts file: " + ex.Message);
        }
    }

    /// <summary>Remove ONLY our block (leaves the rest of the hosts file untouched).</summary>
    public static void Remove()
    {
        try
        {
            if (!File.Exists(AppPaths.HostsFile)) return;
            string cleaned = StripOurBlock(File.ReadAllText(AppPaths.HostsFile)).TrimEnd() + Environment.NewLine;
            File.WriteAllText(AppPaths.HostsFile, cleaned);
            Log.Info("Hosts file entries removed.");
        }
        catch (Exception ex)
        {
            Log.Warn("Could not clean hosts file: " + ex.Message);
        }
    }

    /// <summary>Delete everything between our START and END markers (inclusive).</summary>
    private static string StripOurBlock(string text)
    {
        int start = text.IndexOf(StartMarker, StringComparison.Ordinal);
        if (start < 0) return text;
        int end = text.IndexOf(EndMarker, start, StringComparison.Ordinal);
        if (end < 0) return text[..start];          // malformed: drop from start onward
        end += EndMarker.Length;
        return text[..start] + text[end..];
    }
}
