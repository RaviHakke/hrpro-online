# Repair HRPro index.html that was accidentally copied from chat/rich text.
# Run this script from your hrpro-online folder.

$IndexPath = Join-Path (Get-Location) "public\index.html"
$BackupPath = Join-Path (Get-Location) "public\index_before_repair.html"

if (!(Test-Path $IndexPath)) {
    Write-Host "ERROR: public\index.html not found. Run this from C:\Users\ravi hakke.FTAL\hrpro-online" -ForegroundColor Red
    exit 1
}

Copy-Item $IndexPath $BackupPath -Force

$content = Get-Content $IndexPath -Raw

# Decode HTML entities multiple times because the file may be double encoded.
for ($i = 0; $i -lt 3; $i++) {
    $decoded = [System.Net.WebUtility]::HtmlDecode($content)
    if ($decoded -eq $content) { break }
    $content = $decoded
}

# Remove common rich-text/chat artifacts.
$content = $content -replace '<br\s+aria-hidden="true"\s*/?>', ''
$content = $content -replace '<br\s*/?>', ''

# Rebuild lines and repair CDN include lines that were converted into clickable links.
$lines = $content -split "`r?`n"
$fixed = New-Object System.Collections.Generic.List[string]

foreach ($line in $lines) {
    if ($line -match 'cdn\.tailwindcss\.com') {
        $fixed.Add('    <script src="https://cdn.tailwindcss.com"></script>')
    }
    elseif ($line -match 'font-awesome/6\.4\.0/css/all\.min\.css') {
        $fixed.Add('    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">')
    }
    elseif ($line -match 'xlsx\.full\.min\.js') {
        $fixed.Add('    <script src="https://cdn.sheetjs.com/xlsx-latest/package/dist/xlsx.full.min.js"></script>')
    }
    else {
        $fixed.Add($line)
    }
}

$content = $fixed -join "`r`n"

# Extra cleanup: remove any remaining anchor wrappers around URLs if present.
$content = $content -replace '<a\s+[^>]*href="([^"]+)"[^>]*>(.*?)</a>', '$2'

Set-Content -Path $IndexPath -Value $content -Encoding UTF8

Write-Host "Repair completed." -ForegroundColor Green
Write-Host "Backup saved as public\index_before_repair.html"
Write-Host "First 5 lines now:" -ForegroundColor Cyan
Get-Content $IndexPath -TotalCount 5
