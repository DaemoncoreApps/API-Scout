$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$project = Join-Path $repoRoot 'ApiScout.csproj'
$stage = Join-Path $repoRoot 'Packaging\msix-stage'
$assets = Join-Path $stage 'Assets'
$outDir = Join-Path $repoRoot 'artifacts'
$package = Join-Path $outDir 'API-Scout-1.0.0.0-x64.msix'
$pfx = Join-Path $repoRoot 'Packaging\ApiScout-dev-signing.pfx'
$cer = Join-Path $outDir 'API-Scout-local-signing.cer'
$certificateBuilder = Join-Path $PSScriptRoot 'CertificateBuilder\CertificateBuilder.csproj'
$publish = Join-Path $repoRoot 'Packaging\msix-publish'
$manifest = Join-Path $PSScriptRoot 'AppxManifest.xml'
$logo = Join-Path $repoRoot 'Assets\daemoncore-logo.png'
$makeappx = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'

if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }
New-Item -ItemType Directory -Path $assets -Force | Out-Null

dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o $publish
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'AppxManifest.xml') -Destination (Join-Path $stage 'AppxManifest.xml')
Get-ChildItem -LiteralPath $publish | Copy-Item -Destination $stage -Recurse -Force

Add-Type -AssemblyName System.Drawing
$source = [System.Drawing.Bitmap]::new($logo)
try {
  function Save-Scaled([System.Drawing.Image]$image, [string]$path, [int]$width, [int]$height) {
    $canvas = [System.Drawing.Bitmap]::new($width, $height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($canvas)
    try {
      $graphics.Clear([System.Drawing.Color]::Transparent)
      $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
      $scale = [Math]::Min($width / [double]$image.Width, $height / [double]$image.Height)
      $drawWidth = [int]($image.Width * $scale); $drawHeight = [int]($image.Height * $scale)
      $x = [int](($width - $drawWidth) / 2); $y = [int](($height - $drawHeight) / 2)
      $graphics.DrawImage($image, $x, $y, $drawWidth, $drawHeight)
      $canvas.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $graphics.Dispose(); $canvas.Dispose() }
  }
  function Save-Icon([System.Drawing.Image]$image, [string]$path, [int]$size) {
    $crop = [System.Drawing.Bitmap]::new(700, 700, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($crop)
    try {
      $graphics.Clear([System.Drawing.Color]::Transparent)
      $graphics.DrawImage($image, [System.Drawing.Rectangle]::new(0, 0, 700, 700), [System.Drawing.Rectangle]::new(0, 0, 700, 700), [System.Drawing.GraphicsUnit]::Pixel)
      Save-Scaled $crop $path $size $size
    } finally { $graphics.Dispose(); $crop.Dispose() }
  }
  Save-Scaled $source (Join-Path $assets 'Wide310x150Logo.png') 310 150
  Save-Icon $source (Join-Path $assets 'Square44x44Logo.png') 44
  Save-Icon $source (Join-Path $assets 'Square71x71Logo.png') 71
  Save-Icon $source (Join-Path $assets 'Square150x150Logo.png') 150
  Save-Icon $source (Join-Path $assets 'Square310x310Logo.png') 310
  Save-Icon $source (Join-Path $assets 'StoreLogo.png') 50
} finally { $source.Dispose() }

if (Test-Path $package) { Remove-Item -LiteralPath $package -Force }
& $makeappx pack /d $stage /p $package /o

$signed = $false
$plainPassword = [Guid]::NewGuid().ToString('N')
dotnet run --project $certificateBuilder -c Release -- $pfx $cer $plainPassword
& $signtool sign /fd SHA256 /f $pfx /p $plainPassword $package
$signed = $LASTEXITCODE -eq 0
if (Test-Path $pfx) { Remove-Item -LiteralPath $pfx -Force }
if (-not $signed -and (Test-Path $cer)) { Remove-Item -LiteralPath $cer -Force }
Remove-Item -LiteralPath $publish -Recurse -Force
if ($signed) { Write-Host "Created signed package $package" } else { Write-Host "Created unsigned package $package" }
