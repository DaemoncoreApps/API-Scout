namespace ApiScout.Core;

public sealed record Endpoint(string Method, string Path, string Kind, string File, int Line,
    string Evidence, string Note = "", string BaseUrl = "", string Body = "");
public sealed record SecretFinding(string Provider, string Preview, string File, int Line, string Confidence, string Fingerprint, string Origin = "Working tree", string Commit = "");
public sealed record ScanResult(IReadOnlyList<Endpoint> Endpoints, IReadOnlyList<SecretFinding> Secrets, int FilesRead, IReadOnlyList<string> Notes);
public sealed record ApiResponse(int Status, string Reason, long Milliseconds, string Headers, string Body, bool Truncated);
