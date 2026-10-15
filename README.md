# DaemonCore / API Scout

A native Windows desktop app for local API discovery, possible exposed-secret detection, and explicit API/key testing. No account, telemetry, cloud scanning, or automatic key validation.

## Run

Open `ApiScout.exe` inside the `DaemonCore-ApiScout` release folder. This framework-dependent build needs the .NET 8 Windows Desktop Runtime (already installed on the development machine).

1. Paste an `https://` or `http://` URL to scan a web page and its same-origin JavaScript/assets, or choose **Folder…** for an existing local Git checkout/folder or **File…** for a source/configuration/OpenAPI JSON file.
2. Click **Scan workspace**. Select an endpoint to see its file, line, and evidence.
3. Set the base URL, replace route placeholders, and configure headers/body before clicking **Send**.
4. Review **Secret audit** for masked matches and source locations.
5. In **Key tester**, select GitHub, Stripe, or Custom API; paste your key and click **Fire**. Custom API supports Bearer, Basic (key as username), and custom headers. Keys remain in process memory and are not included in reports. **Clear key** clears the input; strings cannot be guaranteed immediately erased from managed memory.
6. **Export report** saves masked discovery findings only, excluding request headers and test responses. Reports include local file paths.

## What a key test means

GitHub uses authenticated `GET https://api.github.com/user`; Stripe uses `GET https://api.stripe.com/v1/balance`. These issue one explicit request and do not create resources. See the [GitHub user endpoint](https://docs.github.com/en/rest/users/users#get-the-authenticated-user) and [Stripe balance endpoint](https://docs.stripe.com/api/balance/balance_retrieve). Some token types/scopes may not permit these endpoints.

A preset 2xx indicates access to that endpoint, not every API permission. A custom endpoint's 2xx may simply mean the endpoint is public. A 401 reports authentication rejection; 403, 429, redirects, and server/network errors do not establish invalidity. HTTPS is required for key tests except on loopback addresses. TLS validation stays enabled; redirects and automatic cookies are disabled. No retries or batch validation.

## Scan coverage and limits

- Heuristic routes: Express/Fastify, Flask/FastAPI, ASP.NET minimal APIs/controllers, Spring, fetch/axios call sites; OpenAPI/Swagger JSON.
- Secret candidates: common GitHub, AWS access ID, Stripe, Slack, Google API, OpenAI-style, JWT and private-key patterns, plus credential assignments. AWS access IDs alone are not sufficient to authenticate. Matches can include fake/test values and intentionally public identifiers.
- Scans supported source/text/configuration files, including `.env*`, YAML, and key files. OpenAPI YAML endpoint import is not implemented.
- Git repositories are detected automatically. The checked-out tree plus up to 5,000 reachable Git text objects are scanned, including secrets removed from the working tree but still present in history. History reads are local and read-only; no fetch, push, checkout, reset, website crawling, repository execution, or external `$ref` fetching occurs. Clone a remote repository locally before scanning.
- URL scans fetch up to 50 same-origin HTML/JavaScript/assets, capped at 5 MiB per response. They do not execute JavaScript, log in, submit forms, follow cross-origin assets, or validate discovered keys. URL scans are intended for sites you own or are authorized to assess.
- Skips dependency/build folders, symbolic links, binary files, files over 2 MiB; stops after 20,000 eligible files. Notes identify incomplete/skipped reads.
- Static routes can be incomplete or false positives (including commented code). Verify router mount prefixes, dynamic expressions, multiline methods, controller attributes, parameters, and authentication before testing.
- Raw matched keys are not retained in discovery models. Masked previews and SHA-256 fingerprint prefixes support triage. Detectors are not exhaustive; inspect reports before sharing.
- Response display is limited to 2 MiB; request headers and bodies have separate 30-second timeout windows. API tester response content is displayed locally and may contain sensitive server data.

## Development

Requires the .NET 8 SDK on Windows; no third-party packages.

```powershell
dotnet build ApiScout.csproj -c Release
dotnet run --project Tests/ApiScout.Tests.csproj -c Release
dotnet publish ApiScout.csproj -c Release --self-contained false -o ../DaemonCore-ApiScout
```

The test harness uses synthetic keys and loopback HTTP servers, never provider credentials. This is a runnable desktop build, not a signed Microsoft Store package. Store identity, signing, packaging, icons, and submission remain release work.

To create the self-contained x64 MSIX with the Store logos and manifest, run `powershell -ExecutionPolicy Bypass -File Packaging/Package-Msix.ps1`. The package is written to `artifacts/API-Scout-1.0.0.0-x64.msix`. Use the publisher certificate registered for API Scout in Partner Center for final signing.

## MSIX packaging

`work/Package-Msix.ps1` publishes a self-contained `win-x64` build, embeds the DaemonCore logo into the Store tile assets, and creates `outputs/API-Scout-1.0.0.0-x64.msix` with the registered API Scout identity. The package was structurally validated by MakeAppx. The current machine does not permit SignTool to import a certificate, so the delivered MSIX is unsigned; sign it with the API Scout publisher certificate registered in Partner Center before Store submission or local installation.
