using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;

namespace ApiScout.Core;

public sealed class RequestRunner : IDisposable
{
    private readonly HttpClient client = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseDefaultCredentials = false }) { Timeout = TimeSpan.FromSeconds(30) };
    public static Uri BuildUri(string baseUrl, string path)
    {
        path = path.Trim();
        string url = path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || path.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? path : baseUrl.Trim().TrimEnd('/') + "/" + path.TrimStart('/');
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || string.IsNullOrEmpty(uri.Host)) throw new ArgumentException("Enter an HTTP or HTTPS base URL, or a full endpoint URL.");
        if (uri.UserInfo.Length > 0) throw new ArgumentException("Put credentials in the headers field instead of the URL.");
        if (uri.Fragment.Length > 0) throw new ArgumentException("Remove the URL fragment (#…). It is not sent to the server.");
        if (url.Contains('{') || url.Contains('}') || url.Contains("${") || System.Text.RegularExpressions.Regex.IsMatch(uri.AbsolutePath, @"(?:^|/):[A-Za-z_]")) throw new ArgumentException("Replace route placeholders with real values before sending.");
        return uri;
    }
    public async Task<ApiResponse> SendAsync(string method, Uri uri, string headers, string body, CancellationToken token)
    {
        if (!new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE" }.Contains(method)) throw new ArgumentException("Choose a concrete HTTP method.");
        using var request = new HttpRequestMessage(new HttpMethod(method), uri);
        if (!string.IsNullOrWhiteSpace(body)) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        foreach (var line in headers.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int colon = line.IndexOf(':');
            if (colon <= 0) throw new ArgumentException("Headers must use Name: value, one per line.");
            string name = line[..colon].Trim(), value = line[(colon + 1)..].Trim();
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase) || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException($"{name} is managed automatically.");
            if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
            {
                request.Content ??= new StringContent("");
                request.Content.Headers.Remove(name);
                request.Content.Headers.Add(name, value);
            }
            else request.Headers.Add(name, value);
        }
        var timer = Stopwatch.StartNew();
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        // HttpClient's timeout ends at the headers with ResponseHeadersRead; bound the body separately.
        using var bodyTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        bodyTimeout.CancelAfter(TimeSpan.FromSeconds(30));
        await using var stream = await response.Content.ReadAsStreamAsync(bodyTimeout.Token);
        const int limit = 2 * 1024 * 1024;
        using var buffer = new MemoryStream();
        var chunk = new byte[16384];
        while (buffer.Length <= limit)
        {
            int read = await stream.ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, limit + 1 - buffer.Length)), bodyTimeout.Token);
            if (read == 0) break;
            buffer.Write(chunk, 0, read);
        }
        timer.Stop();
        bool truncated = buffer.Length > limit;
        var encoding = Encoding.UTF8;
        try { if (response.Content.Headers.ContentType?.CharSet is { } charset) encoding = Encoding.GetEncoding(charset.Trim('"')); } catch (ArgumentException) { }
        string text = encoding.GetString(buffer.GetBuffer(), 0, (int)Math.Min(buffer.Length, limit));
        return new((int)response.StatusCode, response.ReasonPhrase ?? "", timer.ElapsedMilliseconds, response.Headers + response.Content.Headers.ToString(), text, truncated);
    }
    public void Dispose() => client.Dispose();
}
