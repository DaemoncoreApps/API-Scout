using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using ApiScout.Core;
using Microsoft.Win32;

namespace ApiScout;

public partial class MainWindow : Window
{
    private ScanResult? result;
    private CancellationTokenSource? scanCancellation, requestCancellation, keyCancellation;
    private readonly RequestRunner runner = new();
    public MainWindow() { InitializeComponent(); KeyProvider.SelectedIndex = 0; NavDiscovery.IsChecked = true; }
    private void MinimizeWindow(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void MaximizeWindow(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void CloseWindow(object sender, RoutedEventArgs e) => Close();
    private void Navigate(object sender, RoutedEventArgs e)
    {
        if (MainTabs == null || sender is not RadioButton nav) return;
        int page = int.Parse((string)nav.Tag);
        MainTabs.SelectedIndex = page;
        ScanTargetCard.Visibility = SummaryCards.Visibility = page == 2 ? Visibility.Collapsed : Visibility.Visible;
        PageTitle.Text = page switch { 1 => "Find what shouldn't be exposed.", 2 => "Know what your key can do.", 3 => "Every scan, accounted for.", _ => "See what's in your source." };
        PageSubtitle.Text = page switch { 1 => "Inspect credential candidates, with source evidence and masked values.", 2 => "A single request. A clear result. Straight to the provider.", 3 => "Coverage, exclusions, and diagnostics from your local workspace.", _ => "Discover endpoints and exposed credentials. Test on your terms." };
    }
    private void PickFolder(object sender, RoutedEventArgs e)
    { var dialog = new OpenFolderDialog { Title = "Choose a local repository or folder" }; if (dialog.ShowDialog(this) == true) Target.Text = dialog.FolderName; }
    private void PickFile(object sender, RoutedEventArgs e)
    { var dialog = new OpenFileDialog { Title = "Choose a source, configuration, or OpenAPI JSON file", Filter = "All files|*.*" }; if (dialog.ShowDialog(this) == true) Target.Text = dialog.FileName; }
    private async void StartScan(object sender, RoutedEventArgs e)
    {
        if (scanCancellation != null) return;
        scanCancellation = new(); ScanButton.IsEnabled = false; CancelScanButton.IsEnabled = true;
        ExportButton.IsEnabled = false; result = null; EndpointGrid.ItemsSource = null; SecretsGrid.ItemsSource = null;
        EndpointCount.Text = SecretCount.Text = FileCount.Text = "—"; EndpointEmpty.Visibility = Visibility.Visible;
            Summary.Text = "Preparing scan…";
            var target = Target.Text;
        try
        {
            var progress = new Progress<string>(message => Summary.Text = message);
            if (Uri.TryCreate(target.Trim(), UriKind.Absolute, out var remote) && remote.Scheme is "http" or "https")
            {
                using var webScanner = new WebScanner();
                result = await webScanner.ScanAsync(target, scanCancellation.Token, progress);
            }
            else result = await Task.Run(() => new Scanner().Scan(target, scanCancellation.Token, progress));
            FilterChanged(null!, null!); SecretsGrid.ItemsSource = result.Secrets;
            EndpointCount.Text = result.Endpoints.Count.ToString("N0"); SecretCount.Text = result.Secrets.Count.ToString("N0"); FileCount.Text = result.FilesRead.ToString("N0");
            Summary.Text = $"{result.Endpoints.Count:N0} endpoints  ·  {result.Secrets.Count:N0} key candidates  ·  {result.FilesRead:N0} files";
            ScanNotes.Text = string.Join("\n\n", result.Notes); ExportButton.IsEnabled = true;
        }
        catch (OperationCanceledException) { Summary.Text = "Scan cancelled. Partial findings were discarded."; }
        catch (Exception ex) { Summary.Text = "Scan failed"; ScanNotes.Text = ex.Message; MessageBox.Show(this, ex.Message, "Cannot scan", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { scanCancellation.Dispose(); scanCancellation = null; ScanButton.IsEnabled = true; CancelScanButton.IsEnabled = false; }
    }
    private void CancelScan(object sender, RoutedEventArgs e) => scanCancellation?.Cancel();
    private void FilterChanged(object sender, TextChangedEventArgs e)
    {
        if (EndpointGrid == null) return;
        var q = Search.Text.Trim();
        EndpointGrid.ItemsSource = result?.Endpoints.Where(x => $"{x.Method} {x.Path} {x.Kind} {x.File}".Contains(q, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (EndpointEmpty != null && result != null)
        {
            EndpointEmpty.Visibility = EndpointGrid.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyTitle.Text = "No matching endpoints.";
            EmptyDescription.Text = q.Length > 0 ? "Try another route, method, or filename." : "Review the scan report for supported formats\nand any files that could not be inspected.";
        }
    }
    private void EndpointSelected(object sender, SelectionChangedEventArgs e)
    {
        if (EndpointGrid.SelectedItem is not Endpoint endpoint) return;
        RequestPath.Text = endpoint.Path; RequestBody.Text = endpoint.Body;
        Method.SelectedIndex = -1;
        foreach (ComboBoxItem item in Method.Items) if ((string)item.Content == endpoint.Method) Method.SelectedItem = item;
        if (endpoint.BaseUrl.Length > 0) BaseUrl.Text = endpoint.BaseUrl;
        SourceInfo.Text = $"{Path.GetFileName(endpoint.File)}:{endpoint.Line} · {endpoint.Kind}";
        Evidence.Text = $"{endpoint.File}:{endpoint.Line}\n\n{endpoint.Evidence}\n\n{endpoint.Note}";
    }
    private void SecretSelected(object sender, SelectionChangedEventArgs e)
    {
        if (SecretsGrid.SelectedItem is SecretFinding s) SecretDetails.Text = $"{s.File}:{s.Line}\n{s.Provider} · {s.Confidence} confidence · fingerprint {s.Fingerprint}\nInspect the source to confirm. If a real secret was shared or committed publicly, revoke/rotate it with its provider; deleting the local text alone does not invalidate it.";
    }
    private async void Send(object sender, RoutedEventArgs e)
    {
        if (requestCancellation != null) return;
        try
        {
            var method = (Method.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "";
            if (method.Length == 0) throw new ArgumentException("Choose an HTTP method before sending.");
            var uri = RequestRunner.BuildUri(BaseUrl.Text, RequestPath.Text);
            if (method is not "GET" and not "HEAD" and not "OPTIONS" && MessageBox.Show(this, $"Send {method} to {uri}?\n\nThis request may change data on the destination server.", "Confirm request", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
            requestCancellation = new(); SendButton.IsEnabled = false; CancelRequestButton.IsEnabled = true;
            ResponseStatus.Text = $"Sending {method} to {uri.Host}…"; ResponseBody.Clear();
            var response = await runner.SendAsync(method, uri, RequestHeaders.Text, RequestBody.Text, requestCancellation.Token);
            ResponseStatus.Text = $"{response.Status} {response.Reason} · {response.Milliseconds:N0} ms" + (response.Truncated ? " · truncated at 2 MiB" : "");
            string body = response.Body;
            if (!response.Truncated) try { using var json = JsonDocument.Parse(body); body = JsonSerializer.Serialize(json.RootElement, new JsonSerializerOptions { WriteIndented = true }); } catch (JsonException) { }
            ResponseBody.Text = response.Headers + "\n" + body;
        }
        catch (OperationCanceledException) { ResponseStatus.Text = "Request cancelled or timed out."; }
        catch (Exception ex) { ResponseStatus.Text = "Request failed"; ResponseBody.Text = ex.Message; }
        finally { requestCancellation?.Dispose(); requestCancellation = null; SendButton.IsEnabled = true; CancelRequestButton.IsEnabled = false; }
    }
    private void CancelRequest(object sender, RoutedEventArgs e) => requestCancellation?.Cancel();
    private void Export(object sender, RoutedEventArgs e)
    {
        if (result == null) return;
        var dialog = new SaveFileDialog { FileName = "api-scout-report.json", Filter = "JSON report|*.json" };
        if (dialog.ShowDialog(this) != true) return;
        try { File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true })); Summary.Text = "Masked report exported. Request headers and responses are not included."; }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }
    private void KeyProviderChanged(object sender, SelectionChangedEventArgs e)
    {
        if (KeyUrl == null) return;
        int provider = KeyProvider.SelectedIndex;
        KeyUrl.Text = provider switch { 0 => "https://api.github.com/user", 1 => "https://api.stripe.com/v1/balance", _ => "" };
        KeyUrl.IsReadOnly = provider != 2; KeyAuth.IsEnabled = provider == 2; KeyHeader.IsEnabled = provider == 2;
        KeyAuth.SelectedIndex = provider == 1 ? 1 : 0;
        KeyHeader.Visibility = provider == 2 && KeyAuth.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
        KeyValue.Clear(); KeyResponse.Clear(); KeyStatus.Text = "Ready when you are.";
    }
    private void KeyAuthChanged(object sender, SelectionChangedEventArgs e)
    {
        if (KeyHeader != null) KeyHeader.Visibility = KeyAuth.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
    }
    private async void FireKey(object sender, RoutedEventArgs e)
    {
        if (keyCancellation != null) return;
        string key = KeyValue.Password.Trim();
        try
        {
            var uri = KeyTester.ValidateDestination(KeyUrl.Text);
            var headers = KeyTester.Headers(key, (KeyAuth.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Bearer token", KeyHeader.Text.Trim());
            bool preset = KeyProvider.SelectedIndex != 2;
            keyCancellation = new(); FireButton.IsEnabled = false; CancelKeyButton.IsEnabled = true; KeyProvider.IsEnabled = false;
            KeyStatus.Text = $"Testing against {uri.Host}…"; KeyResponse.Clear();
            var response = await runner.SendAsync("GET", uri, headers, "", keyCancellation.Token);
            KeyStatus.Text = KeyTester.Verdict(response.Status, preset);
            var body = response.Body;
            if (!response.Truncated) try { using var json = JsonDocument.Parse(body); body = JsonSerializer.Serialize(json.RootElement, new JsonSerializerOptions { WriteIndented = true }); } catch (JsonException) { }
            KeyResponse.Text = KeyTester.Sanitize($"GET {uri}\nHTTP {response.Status} {response.Reason} · {response.Milliseconds} ms{(response.Truncated ? " · truncated at 2 MiB" : "")}\n\n{response.Headers}\n{body}", key);
        }
        catch (OperationCanceledException) { KeyStatus.Text = "Cancelled or timed out — key validity is unknown."; }
        catch (Exception ex) { KeyStatus.Text = "Test failed — key validity is unknown."; KeyResponse.Text = KeyTester.Sanitize(ex.Message, key); }
        finally { keyCancellation?.Dispose(); keyCancellation = null; FireButton.IsEnabled = true; CancelKeyButton.IsEnabled = false; KeyProvider.IsEnabled = true; }
    }
    private void CancelKey(object sender, RoutedEventArgs e) => keyCancellation?.Cancel();
    private void ClearKey(object sender, RoutedEventArgs e) { keyCancellation?.Cancel(); KeyValue.Clear(); KeyResponse.Clear(); KeyStatus.Text = "Key cleared."; }
    protected override void OnClosed(EventArgs e) { scanCancellation?.Cancel(); requestCancellation?.Cancel(); keyCancellation?.Cancel(); KeyValue.Clear(); runner.Dispose(); base.OnClosed(e); }
}
