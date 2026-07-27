$ErrorActionPreference = "Continue"

$repoRoot = (Get-Location).Path
$firmwareRoot = Join-Path $repoRoot "sample_data\firmware"
$reportRoot = Join-Path $repoRoot "output\firmware-reports"
$logRoot = Join-Path $repoRoot "output\scan-logs"

New-Item -ItemType Directory -Force -Path $reportRoot | Out-Null
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null

$firmwareFiles = Get-ChildItem `
    -Path $firmwareRoot `
    -Recurse `
    -File `
    -Filter "*.bin"

Write-Host "Repository root: $repoRoot"
Write-Host "Reports folder:  $reportRoot"
Write-Host "Found $($firmwareFiles.Count) firmware images."
Write-Host ""

foreach ($firmware in $firmwareFiles) {
    $relativePath = $firmware.FullName.Substring($repoRoot.Length).TrimStart("\")
    $containerRelativePath = $relativePath.Replace("\", "/")

    $projectName = $firmware.Directory.Name
    $reportName = "$projectName-$($firmware.BaseName).html"
    $logName = "$projectName-$($firmware.BaseName).log"

    $containerFirmwarePath = "/workspace/$containerRelativePath"
    $containerReportPath = "/workspace/output/firmware-reports/$reportName"

    $hostReportPath = Join-Path $reportRoot $reportName
    $hostLogPath = Join-Path $logRoot $logName

    Write-Host "Scanning:"
    Write-Host "  Host input:      $($firmware.FullName)"
    Write-Host "  Container input: $containerFirmwarePath"
    Write-Host "  Host report:     $hostReportPath"
    Write-Host "  Container report:$containerReportPath"
    Write-Host ""

    & docker run --rm `
        -v "${repoRoot}:/workspace" `
        flens:local `
        firmware `
        $containerFirmwarePath `
        --report-out `
        $containerReportPath 2>&1 |
        Tee-Object -FilePath $hostLogPath

    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0 -and (Test-Path $hostReportPath)) {
        Write-Host "SUCCESS: $hostReportPath" -ForegroundColor Green
    }
    else {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "Exit code: $exitCode"
        Write-Host "Expected report: $hostReportPath"
        Write-Host "Log: $hostLogPath"
    }

    Write-Host "----------------------------------------"
}