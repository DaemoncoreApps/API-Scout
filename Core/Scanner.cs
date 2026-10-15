using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ApiScout.Core;

public sealed class Scanner
{
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
        { ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".cs", ".java", ".kt", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config", ".xml", ".env", ".txt", ".md", ".sh", ".ps1", ".properties", ".pem", ".key", ".tf", ".tfvars", ".http", ".rest" };
    private static readonly HashSet<string> Excluded = new(StringComparer.OrdinalIgnoreCase)
        { ".git", ".svn", "node_modules", "bin", "obj", "dist", "build", "coverage", ".venv", "venv", "__pycache__", ".next", "vendor", ".idea", ".vs" };
    private const string Literal = "[\"'`]([^\"'`\\r\\n]+)[\"'`]";
    private static Regex Pattern(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline, TimeSpan.FromMilliseconds(250));
    private static readonly Regex Express = Pattern(@"\b(?:app|router|server|fastify)\s*\.\s*(get|post|put|patch|delete|head|options|all)\s*\(\s*" + Literal);
    private static readonly Regex Chained = Pattern(@"\b(?:app|router)\s*\.route\s*\(\s*" + Literal + @"\s*\)((?:\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\([^;]*?\))+)\s*;");
    private static readonly Regex Python = Pattern(@"@(?:\w+\.)?(?:\w+)\.(get|post|put|patch|delete|head|options|route)\s*\(\s*" + Literal + @"([^\r\n]*)");
    private static readonly Regex Minimal = Pattern(@"\b(\w+)\.Map(Get|Post|Put|Patch|Delete|Methods|Head|Options)\s*\(\s*" + Literal + @"([^\r\n]*)");
    private static readonly Regex Group = Pattern(@"\b(?:var|\w+)\s+(\w+)\s*=\s*(\w+)\.MapGroup\s*\(\s*" + Literal);
    private static readonly Regex Attribute = Pattern(@"\[Http(Get|Post|Put|Patch|Delete|Head|Options)(?:\s*\(\s*" + Literal + @"[^\]]*)?\s*\]");
    private static readonly Regex Spring = Pattern(@"@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?" + Literal);
    private static readonly Regex Client = Pattern(@"\b(?:axios\.(get|post|put|patch|delete|head|options)|fetch)\s*\(\s*" + Literal + @"([^\r\n]*)");
    private static readonly Regex Methods = Pattern("[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']");

    public ScanResult Scan(string target, CancellationToken token, IProgress<string>? progress = null)
    {
        target = System.IO.Path.GetFullPath(target.Trim().Trim('"'));
        if (!Directory.Exists(target) && !System.IO.File.Exists(target)) throw new IOException("Choose an existing local folder or source/OpenAPI JSON file.");
        if ((System.IO.File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0) throw new IOException("Choose a physical folder or file instead of a symbolic link.");
        var results = new List<Endpoint>();
        var secrets = new List<SecretFinding>();
        var notes = new List<string>();
        int files = 0, skipped = 0;
        var root = Directory.Exists(target) ? target : System.IO.Path.GetDirectoryName(target)!;
        var gitRoot = GitHistoryScanner.TryGetRoot(target, notes);
        foreach (var file in Enumerate(target, notes, token))
        {
            token.ThrowIfCancellationRequested();
            var name = System.IO.Path.GetFileName(file);
            if (!Extensions.Contains(System.IO.Path.GetExtension(file)) && !name.StartsWith(".env", StringComparison.OrdinalIgnoreCase) && name is not "credentials" and not "config" and not "id_rsa" and not "id_ed25519") continue;
            if (name.EndsWith(".min.js") || name is "package-lock.json" or "yarn.lock" or "pnpm-lock.yaml") { skipped++; continue; }
            if (files >= 20000) { notes.Add("Stopped at the 20,000-file limit. Scan a smaller folder to cover the remainder."); break; }
            try
            {
                if (new FileInfo(file).Length > 2 * 1024 * 1024) { skipped++; continue; }
                var content = System.IO.File.ReadAllText(file);
                files++;
                if (files % 50 == 0) progress?.Report($"Scanning · {files:N0} files · {results.Count:N0} findings");
                if (content.Contains('\0')) { skipped++; continue; }
                secrets.AddRange(SecretScanner.Scan(content, file));
                if (System.IO.Path.GetExtension(file).Equals(".json", StringComparison.OrdinalIgnoreCase)) ReadOpenApi(content, file, results, notes);
                else ReadSource(content, file, results);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or RegexMatchTimeoutException or JsonException)
            { notes.Add($"Skipped {System.IO.Path.GetRelativePath(root, file)}: {ex.Message}"); }
        }
        notes.Add($"Read {files:N0} files. Skipped {skipped:N0} large, generated, or binary files. Dependency/build folders and symbolic links are excluded. .env and supported configuration files ARE scanned for secrets.");
        if (gitRoot is not null) secrets.AddRange(GitHistoryScanner.Scan(gitRoot, notes, token, progress));
        else notes.Add("The selected target is not inside a Git repository, so Git history was not scanned.");
        notes.Add("Secret matches are candidates, not proof of validity or public exposure. YAML is scanned for secrets but OpenAPI endpoint import currently requires JSON.");
        notes.Add("Static discovery is approximate. Dynamic routes, imported prefixes, authentication and runtime hosts may require manual configuration. No repository code was executed and no network requests were sent.");
        return new(results.Select(e => e with { Evidence = SecretScanner.Redact(e.Evidence), Path = SecretScanner.Redact(e.Path), BaseUrl = SecretScanner.Redact(e.BaseUrl) }).DistinctBy(e => (e.Method, e.Path, e.File, e.Line)).OrderBy(e => e.Path).ThenBy(e => e.Method).ToArray(), secrets, files, notes);
    }

    private static IEnumerable<string> Enumerate(string target, List<string> notes, CancellationToken token)
    {
        if (System.IO.File.Exists(target)) { yield return target; yield break; }
        var stack = new Stack<string>(); stack.Push(target);
        while (stack.Count > 0)
        {
            token.ThrowIfCancellationRequested();
            var dir = stack.Pop();
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { notes.Add($"Cannot read {dir}: {ex.Message}"); continue; }
            foreach (var entry in entries)
            {
                token.ThrowIfCancellationRequested();
                FileAttributes attrs;
                try { attrs = System.IO.File.GetAttributes(entry); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { notes.Add($"Cannot inspect {entry}: {ex.Message}"); continue; }
                if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                if ((attrs & FileAttributes.Directory) != 0) { if (!Excluded.Contains(System.IO.Path.GetFileName(entry))) stack.Push(entry); }
                else yield return entry;
            }
        }
    }

    private static void ReadSource(string text, string file, List<Endpoint> output)
    {
        string ext = System.IO.Path.GetExtension(file).ToLowerInvariant();
        void Add(string method, string path, Match match, string kind = "Route", string note = "")
        {
            if (path.Length > 2048) return;
            int line = 1 + text.AsSpan(0, match.Index).Count('\n');
            int start = text.LastIndexOf('\n', Math.Max(0, match.Index - 1)); start = start < 0 ? 0 : start + 1;
            int end = text.IndexOf('\n', match.Index); if (end < 0) end = text.Length;
            output.Add(new(method.ToUpperInvariant(), path, kind, file, line, text[start..end].Trim(), note));
        }
        if (ext is ".js" or ".jsx" or ".ts" or ".tsx" or ".mjs" or ".cjs")
        {
            foreach (Match m in Express.Matches(text)) Add(m.Groups[1].Value == "all" ? "ANY" : m.Groups[1].Value, m.Groups[2].Value, m, note: "Router mount prefixes may need to be added.");
            foreach (Match m in Chained.Matches(text)) foreach (Match verb in Pattern(@"\.\s*(get|post|put|patch|delete|head|options)\s*\(").Matches(m.Groups[2].Value)) Add(verb.Groups[1].Value, m.Groups[1].Value, m);
            foreach (Match m in Client.Matches(text))
            {
                string method = m.Groups[1].Value;
                var option = Pattern(@"\bmethod\s*:\s*[""'](\w+)[""']").Match(m.Groups[3].Value);
                if (method.Length == 0) method = option.Success ? option.Groups[1].Value : "GET";
                Add(method, m.Groups[2].Value, m, "Client call", "Inferred from a call site; verify method and URL, especially for multiline options.");
            }
        }
        if (ext == ".py") foreach (Match m in Python.Matches(text))
            {
                string verb = m.Groups[1].Value;
                var methods = Methods.Matches(m.Groups[3].Value);
                if (verb.Equals("route", StringComparison.OrdinalIgnoreCase) && methods.Count > 0) foreach (Match method in methods) Add(method.Groups[1].Value, m.Groups[2].Value, m);
                else Add(verb == "route" ? "GET" : verb, m.Groups[2].Value, m, note: "Blueprint/router prefixes and multiline method declarations may need adjustment.");
            }
        if (ext == ".cs")
        {
            var groups = new Dictionary<string, string>();
            foreach (Match g in Group.Matches(text)) groups[g.Groups[1].Value] = (groups.GetValueOrDefault(g.Groups[2].Value) ?? "") + g.Groups[3].Value.TrimEnd('/');
            foreach (Match m in Minimal.Matches(text))
            {
                string path = (groups.GetValueOrDefault(m.Groups[1].Value) ?? "") + m.Groups[3].Value;
                if (m.Groups[2].Value.Equals("Methods", StringComparison.OrdinalIgnoreCase))
                {
                    var methods = Methods.Matches(m.Groups[4].Value);
                    if (methods.Count == 0) Add("ANY", path, m, note: "Resolve the method list before sending.");
                    else foreach (Match method in methods) Add(method.Groups[1].Value, path, m);
                }
                else Add(m.Groups[2].Value, path, m);
            }
            var controller = Pattern(@"\bclass\s+(\w+?)(?:Controller)\b").Match(text);
            var route = Pattern(@"\[Route\s*\(\s*" + Literal).Match(controller.Success ? text[..controller.Index] : "");
            string prefix = route.Success ? route.Groups[1].Value.Replace("[controller]", controller.Groups[1].Value, StringComparison.OrdinalIgnoreCase) : "";
            foreach (Match m in Attribute.Matches(text))
            {
                var path = m.Groups[2].Value;
                path = path.StartsWith('/') || path.StartsWith("~/") ? path.TrimStart('~') : "/" + string.Join("/", new[] { prefix.Trim('/'), path.Trim('/') }.Where(s => s.Length > 0));
                Add(m.Groups[1].Value, path, m, note: "Controller route inferred from the first controller declaration; verify action tokens and additional Route attributes.");
            }
        }
        if (ext is ".java" or ".kt") foreach (Match m in Spring.Matches(text)) Add(m.Groups[1].Value, m.Groups[2].Value, m, note: "Class-level RequestMapping prefixes may need to be added.");
    }

    private static void ReadOpenApi(string text, string file, List<Endpoint> output, List<string> notes)
    {
        using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 64 });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("paths", out var paths) || paths.ValueKind != JsonValueKind.Object || (!root.TryGetProperty("openapi", out _) && !root.TryGetProperty("swagger", out _))) return;
        string baseUrl = "";
        if (root.TryGetProperty("servers", out var servers) && servers.ValueKind == JsonValueKind.Array && servers.GetArrayLength() > 0 && servers[0].TryGetProperty("url", out var server)) baseUrl = server.GetString() ?? "";
        else if (root.TryGetProperty("host", out var host))
        {
            var scheme = root.TryGetProperty("schemes", out var schemes) && schemes.ValueKind == JsonValueKind.Array && schemes.GetArrayLength() > 0 ? schemes[0].GetString() : "https";
            baseUrl = scheme + "://" + host.GetString() + (root.TryGetProperty("basePath", out var bp) ? bp.GetString() : "");
        }
        foreach (var path in paths.EnumerateObject())
        {
            if (path.Value.ValueKind != JsonValueKind.Object) continue;
            foreach (var operation in path.Value.EnumerateObject())
            {
                if (!new[] { "get", "post", "put", "patch", "delete", "head", "options", "trace" }.Contains(operation.Name) || operation.Value.ValueKind != JsonValueKind.Object) continue;
                var needle = JsonSerializer.Serialize(path.Name);
                int index = text.IndexOf(needle, StringComparison.Ordinal);
                var summary = operation.Value.TryGetProperty("summary", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() ?? "" : "";
                output.Add(new(operation.Name.ToUpperInvariant(), path.Name, "OpenAPI", file, index < 0 ? 1 : 1 + text.AsSpan(0, index).Count('\n'), summary.Length > 0 ? summary : $"{operation.Name.ToUpperInvariant()} {path.Name}", "Set path/query parameters, authentication and request body as documented. External references are not fetched. Check operation-specific server overrides.", baseUrl));
            }
        }
    }
}
