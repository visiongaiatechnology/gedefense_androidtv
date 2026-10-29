<#
.SYNOPSIS
    Fuehrt die GeDefense-TV-Verifikationslaeufe aus und protokolliert jeden Exitcode.

.DESCRIPTION
    Fuehrt die vorhandenen Gradle-Checks nacheinander aus:
      - :core:coreCheck        (vendored GeDefense-Core-Verifikationsharness, JavaExec)
      - :tv-core:tvCoreCheck   (TV-Domain-Verifikationsharness, JavaExec)
    Optional:
      - :app:testDebugUnitTest (lokale JVM-Unit-Tests der App, falls vorhanden)
      - :app:lintDebug         (Android-Lint; eigener, langsamer Schritt)

    Das Skript fasst Ergebnisse nicht zusammen und erfindet keine Zahlen: Jeder Schritt wird mit
    seinem realen Exitcode einzeln ausgewiesen. Ein Gesamtergebnis gilt nur dann als PASS, wenn
    alle tatsaechlich ausgefuehrten Schritte Exitcode 0 liefern.

.PARAMETER IncludeAppTests
    Fuehrt zusaetzlich :app:testDebugUnitTest aus (auch wenn noch keine Tests existieren, ist der
    Exitcode aussagekraeftig: der Task laeuft leer durch oder schlaegt real fehl).

.PARAMETER Lint
    Fuehrt zusaetzlich :app:lintDebug aus. Android-Lint ist deutlich langsamer.

.PARAMETER LogPath
    Zieldatei fuer das gemeinsame Evidenz-Log (Standard: .output/test-<Zeitstempel>.log).

.PARAMETER StopOnFirstFailure
    Bricht nach dem ersten Fehlschlag ab.

.PARAMETER ForceCoreCheck
    Fuehrt :core:coreCheck auch auf einem Windows-Host aus. Standard: auf Windows wird der
    Schritt als SKIP (nicht PASS) ausgewiesen, weil der vendored Mobile-Core-Harness
    Verzeichnis-fsync ueber FileChannel nutzt und Win32 das nicht unterstuetzt. Die Verifikation
    erfolgt auf einer Linux-JVM (WSL/CI).

.OUTPUTS
    Exitcode 0 nur, wenn alle ausgefuehrten Schritte Exitcode 0 haben; sonst Exitcode 1.
#>
[CmdletBinding()]
param(
    [switch]$IncludeAppTests,
    [switch]$Lint,
    [string]$LogPath = '',
    [switch]$StopOnFirstFailure,
    [switch]$ForceCoreCheck
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$gradleWrapper = Join-Path $projectRoot 'gradlew.bat'

function Fail {
    param([string]$Message, [int]$Code = 2)
    Write-Host "FEHLER: $Message" -ForegroundColor Red
    exit $Code
}

$steps = New-Object System.Collections.Generic.List[object]
$skippedCoreCheck = $false
if ($env:OS -eq 'Windows_NT' -and -not $ForceCoreCheck) {
    $skippedCoreCheck = $true
    Write-Host 'HINWEIS: :core:coreCheck wird unter Windows uebersprungen (Win32 unterstuetzt Verzeichnis-fsync nicht).' -ForegroundColor Yellow
    Write-Host '         Verifikation auf Linux-JVM (WSL/CI) ausfuehren oder -ForceCoreCheck verwenden (erwartbar BLOCKED).' -ForegroundColor Yellow
} else {
    $steps.Add([pscustomobject]@{ Name = 'Core-Harness (vendored Mobile-Core)'; Task = ':core:coreCheck' }) | Out-Null
}
$steps.Add([pscustomobject]@{ Name = 'TV-Domain-Harness'; Task = ':tv-core:tvCoreCheck' }) | Out-Null
if ($IncludeAppTests) {
    $steps.Add([pscustomobject]@{ Name = 'App-Unit-Tests (debug)'; Task = ':app:testDebugUnitTest' }) | Out-Null
}
if ($Lint) {
    $steps.Add([pscustomobject]@{ Name = 'Android-Lint (debug)'; Task = ':app:lintDebug' }) | Out-Null
}

if (-not (Test-Path -LiteralPath $gradleWrapper -PathType Leaf)) {
    Fail "gradlew.bat nicht gefunden: $gradleWrapper"
}

if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
    $candidate = 'C:\Program Files\Android\Android Studio\jbr'
    if (Test-Path -LiteralPath (Join-Path $candidate 'bin\java.exe') -PathType Leaf) {
        $env:JAVA_HOME = $candidate
        Write-Host "JAVA_HOME nicht gesetzt; verwende Android Studio JBR: $candidate" -ForegroundColor Yellow
    } else {
        Fail 'JAVA_HOME ist nicht gesetzt und Android Studio JBR wurde nicht gefunden.'
    }
}

$sdkDir = $env:ANDROID_HOME
if ([string]::IsNullOrWhiteSpace($sdkDir)) {
    $localProperties = Join-Path $projectRoot 'local.properties'
    if (Test-Path -LiteralPath $localProperties -PathType Leaf) {
        $line = Get-Content -LiteralPath $localProperties | Where-Object { $_ -match '^\s*sdk\.dir\s*=' } | Select-Object -First 1
        if ($line) {
            $sdkDir = ($line -replace '^\s*sdk\.dir\s*=\s*', '').Trim().Replace('\\', '\').Replace('\:', ':')
        }
    }
}
if ([string]::IsNullOrWhiteSpace($sdkDir) -or -not (Test-Path -LiteralPath $sdkDir -PathType Container)) {
    Fail 'Android SDK nicht gefunden (ANDROID_HOME oder sdk.dir in local.properties pruefen).'
}
$env:ANDROID_HOME = $sdkDir
$env:ANDROID_SDK_ROOT = $sdkDir

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $logDirectory = Join-Path $projectRoot '.output'
    if (-not (Test-Path -LiteralPath $logDirectory)) { $null = New-Item -ItemType Directory -Path $logDirectory -Force }
    $LogPath = Join-Path $logDirectory "test-$stamp.log"
} elseif ([System.IO.Path]::IsPathRooted($LogPath) -eq $false) {
    $LogPath = Join-Path $projectRoot $LogPath
}
$logDirectory = Split-Path -Parent $LogPath
if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) {
    $null = New-Item -ItemType Directory -Path $logDirectory -Force
}

$startedAt = Get-Date
$header = @(
    'GeDefense TV - Test-Evidenz (real aufgezeichnet)',
    "Zeitpunkt (Start) : $($startedAt.ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "Arbeitsverzeichnis: $projectRoot",
    "JAVA_HOME         : $env:JAVA_HOME",
    "ANDROID_HOME      : $env:ANDROID_HOME",
    ''
)
$header | Set-Content -LiteralPath $LogPath -Encoding UTF8

Write-Host ''
Write-Host "Test-Evidenz-Log: $LogPath" -ForegroundColor Cyan
Write-Host ''

$results = New-Object System.Collections.Generic.List[object]
$overall = 0

foreach ($step in $steps) {
    $arguments = @($step.Task, '--console=plain')
    $commandLine = "gradlew.bat $($arguments -join ' ')"
    Write-Host "== $($step.Name) ==" -ForegroundColor Cyan
    Write-Host "   $commandLine" -ForegroundColor DarkGray

    $stepStarted = Get-Date
    Push-Location -LiteralPath $projectRoot
    try {
        $output = & $gradleWrapper @arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    $stepDuration = (Get-Date) - $stepStarted

    "`n== $($step.Name) ==" | Out-File -LiteralPath $LogPath -Encoding UTF8 -Append
    "Befehl: $commandLine" | Out-File -LiteralPath $LogPath -Encoding UTF8 -Append
    "Exitcode: $exitCode ; Dauer: $([int]$stepDuration.TotalSeconds) s" | Out-File -LiteralPath $LogPath -Encoding UTF8 -Append
    $output | Out-File -LiteralPath $LogPath -Encoding UTF8 -Append

    $results.Add([pscustomobject]@{
        Name = $step.Name
        Task = $step.Task
        ExitCode = $exitCode
        Seconds = [int]$stepDuration.TotalSeconds
    }) | Out-Null

    if ($exitCode -ne 0) {
        $overall = 1
        Write-Host "   ERGEBNIS: FAIL (Exitcode $exitCode)" -ForegroundColor Red
        if ($StopOnFirstFailure) {
            Write-Host '   Abbruch nach erstem Fehlschlag (-StopOnFirstFailure).' -ForegroundColor Yellow
            break
        }
    } else {
        Write-Host '   ERGEBNIS: PASS (Exitcode 0)' -ForegroundColor Green
    }
}

Write-Host ''
Write-Host 'Zusammenfassung (nur tatsaechlich ausgeführte Schritte):' -ForegroundColor Cyan
$results | Format-Table -AutoSize @{ n = 'Schritt'; e = { $_.Name } }, @{ n = 'Task'; e = { $_.Task } }, @{ n = 'Exitcode'; e = { $_.ExitCode } }, @{ n = 'Sekunden'; e = { $_.Seconds } } | Out-String | Write-Host

$since = (Get-Date) - $startedAt
$footer = @(
    '',
    '--- Zusammenfassung ---',
    "Gesamtdauer: $([int]$since.TotalSeconds) s",
    "Gesamtergebnis: $(if ($overall -eq 0) { 'PASS' } else { 'FAIL' })"
)
if ($skippedCoreCheck) {
    $footer += 'UEBERSPRUNGEN: :core:coreCheck (Win32-Limitierung; Verifikation auf Linux-JVM/WSL erforderlich) - NICHT als PASS gewertet.'
}
$footer | Out-File -LiteralPath $LogPath -Encoding UTF8 -Append

Write-Host "Evidenz-Log: $LogPath" -ForegroundColor Gray
exit $overall
