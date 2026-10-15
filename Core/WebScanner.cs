using System.Net;
using System.Net.Http;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace ApiScout.Core;

public sealed class WebScanner : IDisposable
{
    private const int MaxResources = 50;
    private const int MaxBytesPerResource = 5 * 1024 * 1024;
    private static readonly Regex Script = new("<script\\b[^>]*?\\bsrc\\s*=\\s*[\\\"']([^\\\"']+)", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));
    private static readonly Regex ModulePreload = new("<link\\b[^>]*?\\b(?:href|src)\\s*=\\s*[\\\"']([^\\\"']+)[\\\"'][^>]*>", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));
    private static readonly Regex SourceMap = new("(?:sourceMappingURL=|[\\\"'])([^\\\"'\\s]+\\.map)(?:[\\\"'])?", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));
    private readonly HttpClient client = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseDefaultCredentials = false }) { Timeout = TimeSpan.FromSeconds(20) };

    public async Task<ScanResult> ScanAsync(string target, CancellationToken token, IProgress<string>? progress = null)
    {
        if (!Uri.TryCreate(target.Trim(), UriKind.Absolute, out var start) || start.Scheme is not ("http" or "https")) throw new ArgumentException("Enter an absolute HTTP or HTTPS URL.");
        var origin = new UriBuilder(start) { Path = "/", Query = "", Fragment = "" }.Uri;
        var queue = new Queue<Uri>(); queue.Enqueue(start);
        var queued = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { start.AbsoluteUri };
        var secrets = new List<SecretFinding>(); var notes = new List<string>(); int resources = 0;
        while (queue.Count > 0 && resources < MaxResources)
        {
            token.ThrowIfCancellationRequested();
            var uri = queue.Dequeue();
            progress?.Report($"Fetching remote source · {resources + 1}/{MaxResources} · {uri.Host}");
            var fetched = await FetchAsync(uri, token);
            resources++;
            if (fetched is null) continue;
            var findings = SecretScanner.Scan(fetched.Value.Text, uri.AbsoluteUri)
                .Select(f => f with { Origin = "Remote URL" });
            secrets.AddRange(findings);
            if (!IsHtml(fetched.Value.ContentType, uri)) continue;
            foreach (var asset in FindAssets(fetched.Value.Text, uri))
                if (asset.IsAbsoluteUri && SameOrigin(origin, asset) && queued.Add(asset.AbsoluteUri)) queue.Enqueue(asset);
        }
        if (queue.Count > 0) notes.Add($"Stopped after {MaxResources} same-origin resources. Narrow the URL or scan individual assets for a deeper pass.");
        notes.Add($"Fetched {resources:N0} same-origin remote resources. HTML and JavaScript responses were inspected; no JavaScript was executed.");
        notes.Add("Remote URL scanning does not log in, submit forms, follow cross-origin assets, or validate discovered keys. A finding is a possible exposed secret, not proof that it is valid.");
        return new(Array.Empty<Endpoint>(), secrets.DistinctBy(f => (f.Fingerprint, f.File, f.Line)).ToArray(), resources, notes);
    }

    private async Task<(string Text, string ContentType)?> FetchAsync(Uri uri, CancellationToken token)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.ParseAdd("DaemonCore-ApiScout/0.1");
            request.Headers.Accept.ParseAdd("text/html, application/javascript, text/javascript, application/json, */*;q=0.1");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
            if ((int)response.StatusCode is < 200 or >= 300) return null;
            if (response.Content.Headers.ContentLength > MaxBytesPerResource) return null;
            await using var stream = await response.Content.ReadAsStreamAsync(token);
            using var buffer = new MemoryStream(); var chunk = new byte[16384];
            while (buffer.Length < MaxBytesPerResource)
            {
                int read = await stream.ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, MaxBytesPerResource - buffer.Length)), token);
                if (read == 0) break; buffer.Write(chunk, 0, read);
            }
            var encoding = Encoding.UTF8;
            try { if (response.Content.Headers.ContentType?.CharSet is { } charset) encoding = Encoding.GetEncoding(charset.Trim('"')); } catch (ArgumentException) { }
            return (encoding.GetString(buffer.ToArray()), response.Content.Headers.ContentType?.MediaType ?? "");
        }
        catch (HttpRequestException) { return null; }
        catch (TaskCanceledException) when (!token.IsCancellationRequested) { return null; }
    }

    private static IEnumerable<Uri> FindAssets(string html, Uri page)
    {
        var values = Script.Matches(html).Select(m => m.Groups[1].Value)
            .Concat(ModulePreload.Matches(html).Select(m => m.Groups[1].Value))
            .Concat(SourceMap.Matches(html).Select(m => m.Groups[1].Value));
        foreach (var value in values.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (value.StartsWith("data:", StringComparison.OrdinalIgnoreCase) || value.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)) continue;
            if (Uri.TryCreate(page, WebUtility.HtmlDecode(value), out var asset) && asset.Scheme is "http" or "https") yield return asset;
        }
    }

    private static bool SameOrigin(Uri left, Uri right) => left.Scheme == right.Scheme && left.Host.Equals(right.Host, StringComparison.OrdinalIgnoreCase) && left.Port == right.Port;
    private static bool IsHtml(string contentType, Uri uri) => contentType.Contains("html", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(contentType) && (uri.AbsolutePath.EndsWith('/') || !Path.HasExtension(uri.AbsolutePath));
    public void Dispose() => client.Dispose();
}
