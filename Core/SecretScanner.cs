using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ApiScout.Core;

public static class SecretScanner
{
    private sealed record Rule(string Name, string Pattern, string Confidence = "High");
    private static readonly Rule[] Rules =
    [
        new("AWS access key ID", @"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        new("GitHub token", @"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
        new("Stripe secret/restricted key", @"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b"),
        new("Slack token", @"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b"),
        new("Google API key", @"\bAIza[A-Za-z0-9_-]{35}\b"),
        new("OpenAI-style key", @"\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255}\b", "Medium"),
        new("JWT / bearer token", @"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "Medium"),
        new("Private key", @"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
        new("Credential assignment", "(?im)[\"']?(?:[A-Za-z0-9_]*(?:api[_-]?key|api[_-]?token|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|aws_secret_access_key))[\"']?\\s*[:=]\\s*[\"']?([^\\s\"'`,;#}{]{8,256})", "Medium")
    ];
    private static readonly (Rule Rule, Regex Regex)[] Compiled = Rules.Select(r => (r, new Regex(r.Pattern, RegexOptions.None, TimeSpan.FromMilliseconds(250)))).ToArray();
    private static bool Placeholder(string value) => value.Contains("example", StringComparison.OrdinalIgnoreCase) || value.Contains("placeholder", StringComparison.OrdinalIgnoreCase) || value.Contains("your_", StringComparison.OrdinalIgnoreCase) || value.Contains("your-", StringComparison.OrdinalIgnoreCase) || value.Contains("changeme", StringComparison.OrdinalIgnoreCase) || value.StartsWith('$') || value.StartsWith("process.env") || value.StartsWith("os.getenv") || value.StartsWith("os.environ") || value.StartsWith("Environment.") || value.All(c => c == value[0]);
    public static IReadOnlyList<SecretFinding> Scan(string text, string file)
    {
        var results = new List<SecretFinding>();
        var seen = new HashSet<(int, string)>();
        foreach (var (rule, regex) in Compiled)
        {
            foreach (Match match in regex.Matches(text))
            {
                var value = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                if (Placeholder(value)) continue;
                int line = 1 + text.AsSpan(0, match.Index).Count('\n');
                string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..12];
                if (!seen.Add((line, fingerprint))) continue;
                results.Add(new(rule.Name, rule.Name == "Private key" ? "[private key block]" : "••••••••" + value[^4..], file, line, rule.Confidence, fingerprint));
            }
        }
        return results;
    }
    public static string Redact(string text)
    {
        foreach (var (_, regex) in Compiled)
            text = regex.Replace(text, m => m.Groups.Count > 1 ? m.Value[..(m.Groups[1].Index - m.Index)] + "[REDACTED]" : "[REDACTED]");
        return text;
    }
}
