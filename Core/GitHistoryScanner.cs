using System.Diagnostics;
using System.IO;
using System.Text;

namespace ApiScout.Core;

public static class GitHistoryScanner
{
    private const int MaxObjects = 5000;
    private const long MaxBlobBytes = 2 * 1024 * 1024;
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".cs", ".java", ".kt", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config", ".xml", ".env", ".txt", ".md", ".sh", ".ps1", ".properties", ".pem", ".key", ".tf", ".tfvars", ".http", ".rest"
    };

    public static string? TryGetRoot(string target, List<string> notes)
    {
        var start = Directory.Exists(target) ? target : Path.GetDirectoryName(target);
        if (string.IsNullOrWhiteSpace(start)) return null;
        var result = Run(start, "rev-parse", "--show-toplevel");
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Stdout)) return null;
        return Path.GetFullPath(result.Stdout.Trim());
    }

    public static IReadOnlyList<SecretFinding> Scan(string root, List<string> notes, CancellationToken token, IProgress<string>? progress = null)
    {
        var objects = Run(root, "rev-list", "--objects", "--all");
        if (objects.ExitCode != 0)
        {
            notes.Add("Git history was not scanned: " + (string.IsNullOrWhiteSpace(objects.Stderr) ? "the repository has no reachable commits or Git is unavailable." : objects.Stderr.Trim()));
            return Array.Empty<SecretFinding>();
        }

        var findings = new List<SecretFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var candidates = objects.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries))
            .Where(parts => parts.Length == 2 && IsTextPath(parts[1]))
            .Select(parts => (Oid: parts[0], Path: parts[1].Replace('/', Path.DirectorySeparatorChar)))
            .Where(item => seen.Add(item.Oid))
            .Take(MaxObjects)
            .ToArray();

        if (candidates.Length == MaxObjects) notes.Add($"Git history scan stopped after {MaxObjects:N0} reachable text objects.");
        for (var i = 0; i < candidates.Length; i++)
        {
            token.ThrowIfCancellationRequested();
            var candidate = candidates[i];
            if (i % 50 == 0) progress?.Report($"Scanning Git history · {i:N0}/{candidates.Length:N0} objects · {findings.Count:N0} findings");
            var blob = Run(root, "cat-file", "blob", candidate.Oid);
            if (blob.ExitCode != 0 || blob.Bytes.LongLength > MaxBlobBytes || blob.Bytes.Contains((byte)0)) continue;
            string content;
            try { content = Encoding.UTF8.GetString(blob.Bytes); }
            catch (DecoderFallbackException) { continue; }
            foreach (var finding in SecretScanner.Scan(content, Path.Combine(root, candidate.Path)))
            {
                var commit = FindCommit(root, candidate.Oid);
                findings.Add(finding with { Origin = "Git history", Commit = commit.Length > 8 ? commit[..8] : commit });
            }
        }
        notes.Add($"Scanned {candidates.Length:N0} reachable Git text objects for secrets. History matches are masked and include a short commit reference when available.");
        return findings.DistinctBy(f => (f.Fingerprint, f.File, f.Line)).ToArray();
    }

    private static string FindCommit(string root, string oid)
    {
        var result = Run(root, "log", "--all", "--find-object=" + oid, "-1", "--format=%H");
        return result.ExitCode == 0 ? result.Stdout.Trim() : "";
    }

    private static bool IsTextPath(string path)
    {
        var name = Path.GetFileName(path);
        if (name.StartsWith(".env", StringComparison.OrdinalIgnoreCase) || name is "credentials" or "config" or "id_rsa" or "id_ed25519") return true;
        return TextExtensions.Contains(Path.GetExtension(path));
    }

    private static (int ExitCode, string Stdout, string Stderr, byte[] Bytes) Run(string workingDirectory, params string[] args)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo("git") { WorkingDirectory = workingDirectory, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);
        process.Start();
        using var output = new MemoryStream();
        var stdout = process.StandardOutput.BaseStream.CopyToAsync(output);
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit(30000);
        if (!process.HasExited) { try { process.Kill(true); } catch { } return (-1, "", "Git command timed out.", Array.Empty<byte>()); }
        stdout.GetAwaiter().GetResult();
        return (process.ExitCode, Encoding.UTF8.GetString(output.ToArray()), stderr.GetAwaiter().GetResult(), output.ToArray());
    }
}
