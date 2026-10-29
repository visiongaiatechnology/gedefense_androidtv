<#
.SYNOPSIS
    Fuehrt einen GeDefense-TV-Gradle-Build aus und protokolliert das reale Ergebnis.

.DESCRIPTION
    Dünner, ehrlicher Wrapper um gradlew.bat. Das Skript ersetzt keine Gradle-Logik und
    interpretiert Ergebnisse nicht um: Es meldet den tatsaechlichen Exitcode und schreibt auf
    Wunsch ein Evidenz-Log. Es behauptet niemals einen erfolgreichen Build ohne Exitcode 0.

    Umgebung:
      - JAVA_HOME muss auf ein JDK 17 zeigen (Standard: Android Studio JBR).
      - Das Android SDK wird aus ANDROID_HOME bzw. local.properties (sdk.dir) ermittelt.

.PARAMETER Tasks
    Gradle-Tasks, die ausgefuehrt werden (Standard: assembleDebug).
    Beispiele: assembleDebug, assembleRelease, lintDebug, :tv-core:tvCoreCheck.

.PARAMETER Release
    Kurzform fuer -Tasks assembleRelease (nur wirksam, wenn -Tasks nicht explizit gesetzt ist).

.PARAMETER Clean
    Fuehrt vor dem Build 'clean' aus.

.PARAMETER LogPath
    Zieldatei fuer das Evidenz-Log. Standard: .output/build-<Zeitstempel>.log
    (Verzeichnis wird angelegt; .output/ ist per .gitignore ausgeschlossen).

.PARAMETER NoDaemon
    Startet Gradle ohne Daemon (--no-daemon), z. B. fuer reproduzierbare CI-Laeufe.

.EXAMPLE
    .\tools\build.ps1
    .\tools\build.ps1 -Release -Clean
    .\tools\build.ps1 -Tasks assembleDebug,lintDebug -LogPath .output\verify-1.log

.OUTPUTS
    Exitcode des Gradle-Laufs (0 = OK). Das Skript selbst faelscht keinen Exitcode.
#>
[CmdletBinding()]
param(
    [string[]]$Tasks = @(),
    [switch]$Release,
    [switch]$Clean,
    [string]$LogPath = '',
    [switch]$NoDaemon
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

function Resolve-Toolchain {
    param([string]$Root)

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
    if (-not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME 'bin\java.exe') -PathType Leaf)) {
        Fail "JAVA_HOME zeigt nicht auf ein gueltiges JDK: $env:JAVA_HOME"
    }

    $sdkDir = $env:ANDROID_HOME
    if ([string]::IsNullOrWhiteSpace($sdkDir)) {
        $localProperties = Join-Path $Root 'local.properties'
        if (Test-Path -LiteralPath $localProperties -PathType Leaf) {
            $line = Get-Content -LiteralPath $localProperties | Where-Object { $_ -match '^\s*sdk\.dir\s*=' } | Select-Object -First 1
            if ($line) {
                $sdkDir = ($line -replace '^\s*sdk\.dir\s*=\s*', '').Trim()
                # Properties-Escaping (Doppelbackslash, escaped colon) aufloesen.
                $sdkDir = $sdkDir.Replace('\\', '\').Replace('\:', ':')
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($sdkDir) -or -not (Test-Path -LiteralPath $sdkDir -PathType Container)) {
        Fail 'Android SDK nicht gefunden (ANDROID_HOME oder sdk.dir in local.properties pruefen).'
    }
    $env:ANDROID_HOME = $sdkDir
    $env:ANDROID_SDK_ROOT = $sdkDir
    Write-Host "JAVA_HOME : $env:JAVA_HOME"
    Write-Host "SDK       : $sdkDir"
}

Resolve-Toolchain -Root $projectRoot

$taskList = @()
if ($Tasks.Count -gt 0) {
    $taskList += $Tasks
} elseif ($Release) {
    $taskList += 'assembleRelease'
} else {
    $taskList += 'assembleDebug'
}
if ($Clean) {
    $taskList = @('clean') + $taskList
}

$arguments = @()
foreach ($task in $taskList) { $arguments += $task }
if ($NoDaemon) { $arguments += '--no-daemon' }
$arguments += '--console=plain'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $logDirectory = Join-Path $projectRoot '.output'
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        $null = New-Item -ItemType Directory -Path $logDirectory -Force
    }
    $LogPath = Join-Path $logDirectory "build-$stamp.log"
} else {
    $logDirectory = Split-Path -Parent $LogPath
    if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) {
        $null = New-Item -ItemType Directory -Path $logDirectory -Force
    }
}
if ([System.IO.Path]::IsPathRooted($LogPath) -eq $false) {
    $LogPath = Join-Path $projectRoot $LogPath
}

$commandLine = "gradlew.bat $($arguments -join ' ')"
$startedAt = Get-Date
Write-Host ''
Write-Host "Befehl   : $commandLine" -ForegroundColor Cyan
Write-Host "Arbeitsdir: $projectRoot" -ForegroundColor Cyan
Write-Host "Log       : $LogPath" -ForegroundColor Cyan
Write-Host ''

Push-Location -LiteralPath $projectRoot
try {
    $output = & $gradleWrapper @arguments 2>&1
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

$output | ForEach-Object { $_ }

$duration = (Get-Date) - $startedAt
$header = @(
    'GeDefense TV - Build-Evidenz (real aufgezeichnet)',
    "Zeitpunkt (Start) : $($startedAt.ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "Dauer             : $([int]$duration.TotalSeconds) s",
    "Arbeitsverzeichnis: $projectRoot",
    "Befehl            : $commandLine",
    "JAVA_HOME         : $env:JAVA_HOME",
    "ANDROID_HOME      : $env:ANDROID_HOME",
    "Exitcode          : $exitCode",
    '',
    '--- Rohausgabe (stdout+stderr) ---'
)
$header | Set-Content -LiteralPath $LogPath -Encoding UTF8
$output | Out-File -LiteralPath $LogPath -Encoding UTF8 -Append

Write-Host ''
if ($exitCode -eq 0) {
    Write-Host "ERGEBNIS: Build-Tasks erfolgreich beendet (Exitcode 0)." -ForegroundColor Green
} else {
    Write-Host "ERGEBNIS: Build FEHLGESCHLAGEN (Exitcode $exitCode)." -ForegroundColor Red
}
Write-Host "Evidenz-Log: $LogPath" -ForegroundColor Gray
exit $exitCode
