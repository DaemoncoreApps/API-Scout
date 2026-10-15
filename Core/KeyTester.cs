namespace ApiScout.Core;

public static class KeyTester
{
    public static string Verdict(int status, bool authenticatedPreset) => status switch
    {
        >= 200 and < 300 => authenticatedPreset ? "Accepted — this key can access the selected endpoint." : "Request succeeded — a public endpoint may accept requests without checking the key.",
        401 => "Authentication rejected — the key may be invalid, expired, revoked, or incorrectly configured.",
        403 => "Access denied — permissions, account restrictions, or rate limits may be responsible. Key validity is inconclusive.",
        429 => "Rate limited — wait before retrying. Key validity is inconclusive.",
        >= 300 and < 400 => "Redirect returned — not followed. Key validity is inconclusive.",
        >= 500 => "Provider error — key validity is inconclusive.",
        _ => "Request not accepted — check the URL, authentication format, and response. Key validity is inconclusive."
    };
    public static Uri ValidateDestination(string url)
    {
        var uri = RequestRunner.BuildUri("", url);
        if (uri.Scheme != "https" && !uri.IsLoopback) throw new ArgumentException("Key tests require HTTPS, except on localhost.");
        return uri;
    }
    public static string Headers(string key, string auth, string headerName)
    {
        key = key.Trim();
        if (key.Length == 0) throw new ArgumentException("Paste an API key first.");
        if (key.Any(char.IsControl)) throw new ArgumentException("The key contains control characters. Paste a single key.");
        if (auth == "Custom header" && !System.Text.RegularExpressions.Regex.IsMatch(headerName, @"^[A-Za-z0-9-]+$")) throw new ArgumentException("Enter a valid authentication header name.");
        string credentials = auth switch
        {
            "Basic (key as username)" => "Authorization: Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(key + ":")),
            "Custom header" => headerName + ": " + key,
            _ => "Authorization: Bearer " + key
        };
        return credentials + "\nUser-Agent: ApiScout/0.1\nAccept: application/json";
    }
    public static string Sanitize(string text, string key)
    {
        if (key.Length > 0)
            foreach (var representation in new[] { key, Uri.EscapeDataString(key), Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(key + ":")) }) text = text.Replace(representation, "[REDACTED]", StringComparison.Ordinal);
        return SecretScanner.Redact(text);
    }
}
