using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using ApiScout.Core;

var root = Path.Combine(Path.GetTempPath(), "ApiScout-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
int assertions = 0;
void Check(bool ok, string message) { assertions++; if (!ok) throw new Exception(message); }
void Reject(Action action, string message) { try { action(); } catch (ArgumentException) { assertions++; return; } throw new Exception(message); }
try
{
    File.WriteAllText(Path.Combine(root, "routes.ts"), "app.get('/users/:id', handler);\nrouter.post('/users', handler);\nfetch('https://example.invalid/status');\naxios.delete('/users/1');");
    File.WriteAllText(Path.Combine(root, "api.py"), "@app.route('/items', methods=['GET', 'POST'])\ndef items(): pass\n@router.patch('/items/{id}')\ndef update(): pass");
    File.WriteAllText(Path.Combine(root, "Api.cs"), "var api = app.MapGroup(\"/api\");\napi.MapGet(\"/health\", () => \"ok\");\n[Route(\"api/[controller]\")]\nclass UsersController {\n[HttpGet(\"{id}\")] public void Get() {}\n}");
    File.WriteAllText(Path.Combine(root, "openapi.json"), """{"openapi":"3.0.3","servers":[{"url":"https://example.invalid/v1"}],"paths":{"/pets":{"get":{"summary":"List pets"},"post":{}}}}""");
    var synthetic = "ghp_" + "AbCdEf0123456789" + "GhIjKl9876543210" + "MnOp";
    File.WriteAllText(Path.Combine(root, ".env.local"), "GITHUB_TOKEN=" + synthetic + "\nCLIENT_SECRET=Demo_4z7q9v2r6s8t1u3w\nAPI_KEY=your_key_here\n");
    Directory.CreateDirectory(Path.Combine(root, "node_modules"));
    File.WriteAllText(Path.Combine(root, "node_modules", "excluded.js"), "app.get('/excluded', handler)");
    var result = new Scanner().Scan(root, CancellationToken.None);
    Check(result.Endpoints.Any(e => e.Path == "/users/:id" && e.Method == "GET" && e.Line == 1), "Express discovery and line numbers");
    Check(result.Endpoints.Any(e => e.Path == "/items" && e.Method == "POST"), "Flask multiple methods");
    Check(result.Endpoints.Any(e => e.Path == "/items/{id}" && e.Method == "PATCH"), "FastAPI route");
    Check(result.Endpoints.Any(e => e.Path == "/api/health"), "Minimal API group prefix");
    Check(result.Endpoints.Any(e => e.Path == "/api/Users/{id}"), "Controller prefix");
    Check(result.Endpoints.Count(e => e.Kind == "OpenAPI") == 2, "OpenAPI operations");
    Check(result.Endpoints.First(e => e.Kind == "OpenAPI").BaseUrl == "https://example.invalid/v1", "OpenAPI host");
    Check(!result.Endpoints.Any(e => e.Path == "/excluded"), "Dependency exclusions");
    Check(result.Secrets.Any(s => s.Provider == "GitHub token" && s.Line == 1), "Provider key detection in hidden env file");
    Check(result.Secrets.Any(s => s.Provider == "Credential assignment" && s.Line == 2), "Generic secret detection");
    Check(!result.Secrets.Any(s => s.Line == 3), "Placeholder suppression");
    Check(!JsonSerializer.Serialize(result).Contains(synthetic), "Report excludes full key");
    Check(!SecretScanner.Redact("const secret = '" + synthetic + "'").Contains(synthetic), "Evidence redaction");
    using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
    try { new Scanner().Scan(root, cancelled.Token); throw new Exception("Cancellation ignored"); } catch (OperationCanceledException) { assertions++; }
    Check(RequestRunner.BuildUri("https://example.invalid/v1", "/users?q=hello").AbsoluteUri == "https://example.invalid/v1/users?q=hello", "Base path preservation");
    Reject(() => RequestRunner.BuildUri("https://example.invalid", "/users/{id}"), "Placeholder should fail");
    Reject(() => RequestRunner.BuildUri("https://example.invalid", "/users/:id"), "Express placeholder should fail");
    Reject(() => RequestRunner.BuildUri("", "https://user:pass@example.invalid/"), "URL credentials should fail");
    Reject(() => KeyTester.ValidateDestination("http://example.invalid"), "Plain HTTP key destination should fail");
    Check(KeyTester.ValidateDestination("http://127.0.0.1:1234").IsLoopback, "Local key testing");
    Reject(() => KeyTester.Headers("abc\r\nInjected: true", "Bearer token", ""), "Header injection should fail");
    Check(KeyTester.Verdict(403, true).Contains("inconclusive"), "403 must not mean bad key");
    Check(KeyTester.Verdict(429, true).Contains("inconclusive"), "429 must not mean bad key");
    Check(KeyTester.Verdict(200, false).Contains("public endpoint"), "Generic 200 not proof of valid key");
    Check(!KeyTester.Sanitize(synthetic, synthetic).Contains(synthetic), "Response echo redaction");

    var gitRoot = Path.Combine(Path.GetTempPath(), "ApiScout-git-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(gitRoot);
    void Git(params string[] args)
    {
        using var git = new Process { StartInfo = new ProcessStartInfo("git") { WorkingDirectory = gitRoot, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        foreach (var arg in args) git.StartInfo.ArgumentList.Add(arg);
        git.Start(); git.WaitForExit();
        if (git.ExitCode != 0) throw new Exception("Git test command failed: " + git.StandardError.ReadToEnd());
    }
    try
    {
        Git("init", "--quiet"); Git("config", "user.email", "test@example.invalid"); Git("config", "user.name", "ApiScout test");
        File.WriteAllText(Path.Combine(gitRoot, "settings.env"), "API_KEY=" + synthetic + "\n"); Git("add", "."); Git("commit", "--quiet", "-m", "secret");
        File.WriteAllText(Path.Combine(gitRoot, "settings.env"), "API_KEY=removed-from-working-tree\n"); Git("add", "."); Git("commit", "--quiet", "-m", "remove-secret");
        var history = new Scanner().Scan(gitRoot, CancellationToken.None);
        Check(history.Secrets.Any(s => s.Origin == "Git history" && s.Commit.Length == 8 && s.Provider == "GitHub token"), "Reachable Git history secret detection");
        Check(history.Notes.Any(n => n.Contains("reachable Git text objects", StringComparison.OrdinalIgnoreCase)), "Git history scan note");
    }
    finally
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(gitRoot, "*", SearchOption.AllDirectories).Reverse())
            try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
        Directory.Delete(gitRoot, recursive: true);
    }

    using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    async Task<string> Respond(int status, string body, string extra = "")
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await listener.AcceptTcpClientAsync(timeout.Token);
        await using var stream = socket.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        var request = new StringBuilder();
        while (await reader.ReadLineAsync(timeout.Token) is { Length: > 0 } line) request.AppendLine(line);
        var data = Encoding.UTF8.GetBytes(body);
        var header = Encoding.ASCII.GetBytes($"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {data.Length}\r\n{extra}Connection: close\r\n\r\n");
        await stream.WriteAsync(header, timeout.Token); await stream.WriteAsync(data, timeout.Token);
        return request.ToString();
    }
    using var runner = new RequestRunner();
    var server = Respond(200, "{\"ok\":true}");
    var response = await runner.SendAsync("GET", new Uri($"http://127.0.0.1:{port}/test"), KeyTester.Headers("synthetic-test-key", "Bearer token", ""), "", CancellationToken.None);
    var captured = await server;
    Check(response.Status == 200 && response.Body.Contains("true"), "HTTP response capture");
    Check(captured.Contains("Authorization: Bearer synthetic-test-key"), "Key auth sent correctly");
    server = Respond(302, "{}", "Location: http://127.0.0.1:1/should-not-follow\r\n");
    response = await runner.SendAsync("GET", new Uri($"http://127.0.0.1:{port}/redirect"), "", "", CancellationToken.None); await server;
    Check(response.Status == 302, "No redirects");
    server = Respond(401, "{\"error\":\"unauthorized\"}");
    response = await runner.SendAsync("GET", new Uri($"http://127.0.0.1:{port}/reject"), "", "", CancellationToken.None); await server;
    Check(response.Status == 401 && KeyTester.Verdict(response.Status, true).StartsWith("Authentication rejected"), "Rejected key handling");
    server = Respond(200, new string('x', 2 * 1024 * 1024 + 1));
    response = await runner.SendAsync("GET", new Uri($"http://127.0.0.1:{port}/large"), "", "", CancellationToken.None); await server;
    Check(response.Truncated && response.Body.Length == 2 * 1024 * 1024, "Response size cap");
    Console.WriteLine($"PASS: {assertions} assertions, including local HTTP integration checks. No external APIs contacted.");
}
finally { Directory.Delete(root, recursive: true); }
