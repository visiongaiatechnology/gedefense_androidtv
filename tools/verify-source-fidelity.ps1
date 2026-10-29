<#
.SYNOPSIS
    Prueft die Byte-Identitaet des vendored GeDefense-Core gegen SOURCE-MANIFEST.sha256.

.DESCRIPTION
    GeDefense TV bindet das Mobile-Core-Modul (GeDefense Mobile 0.28.0-beta1, VersionCode 59)
    unveraendert ein. Dieses Skript berechnet SHA-256 fuer jede Datei unter core/ und vergleicht
    sie mit dem Manifest. Jede Abweichung ist ein Release-Blocker, bis die Provenienz bewusst
    aktualisiert wurde (siehe core/PROVENANCE.md).

    Standardmodus ist read-only: es werden keine Dateien geschrieben. Der Manifest wird nur mit
    -Generate neu erzeugt, und das ist ausschliesslich nach einer bewussten Neuimport-Entscheidung
    zulaessig (siehe core/PROVENANCE.md).

.PARAMETER Root
    Projektwurzel (Standard: Elternverzeichnis dieses Skripts).

.PARAMETER Manifest
    Manifestpfad relativ zu -Root (Standard: SOURCE-MANIFEST.sha256).

.PARAMETER Generate
    Erzeugt den Manifest aus dem aktuellen core/-Baum neu. Nur nach expliziter Neuimport-Freigabe
    verwenden. Ueberschreibt den bestehenden Manifest.

.PARAMETER AllowExtra
    Zusaetzliche Dateien unter core/, die nicht aus dem Mobile-Quellstand stammen, aber bewusst
    vom TV-Projekt dort abgelegt werden (Standard: core/PROVENANCE.md). Sie werden als HINWEIS
    gemeldet, nicht als Blocker. -Strict wertet auch diese als Fehler.

.PARAMETER Strict
    Jede nicht im Manifest gelistete Datei ist ein Fehler, auch dokumentierte Ausnahmen.

.PARAMETER Quiet
    Unterdrueckt Statusausgaben; Exitcode bleibt aussagekraeftig.

.OUTPUTS
    Exitcode 0  = alle Dateien vorhanden und byte-identisch, keine unerwarteten Zusatzdateien.
    Exitcode 1  = Abweichung (Mismatch, fehlende oder zusaetzliche Datei) -> Release-Blocker.
    Exitcode 2  = Aufruffehler (Manifest fehlt/leer/ungueltig, Root fehlt).

.NOTES
    Dieses Skript belegt ausschliesslich Dateiintegritaet, nicht die Sicherheit des Codes.
    Es ersetzt keinen Build, keinen Test und kein Security-Audit.
#>
[CmdletBinding()]
param(
    [string]$Root = '',
    [string]$Manifest = 'SOURCE-MANIFEST.sha256',
    [switch]$Generate,
    [string[]]$AllowExtra = @('core/PROVENANCE.md'),
    [switch]$Strict,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    param([string]$Message, [string]$Color = 'Gray')
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

function Exit-With {
    param([int]$Code, [string]$Message = '')
    if ($Message) { Write-Status $Message $(if ($Code -eq 0) { 'Green' } else { 'Red' }) }
    exit $Code
}

function Get-ProjectRoot {
    param([string]$Explicit)
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        return (Resolve-Path -LiteralPath $Explicit).Path
    }
    $candidate = Split-Path -Parent $PSScriptRoot
    return (Resolve-Path -LiteralPath $candidate).Path
}

function Get-ManifestEntries {
    param([string]$Path)
    $entries = @()
    $lineNo = 0
    foreach ($line in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        $lineNo++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith('#')) { continue }
        $match = [regex]::Match($line, '^([0-9a-fA-F]{64})[ \t]{2}(.+)$')
        if (-not $match.Success) {
            throw "Ungueltiges Manifestformat in Zeile ${lineNo}: '$line'"
        }
        $entries += [pscustomobject]@{
            Hash = $match.Groups[1].Value.ToLowerInvariant()
            Path = $match.Groups[2].Value.Trim().Replace('\', '/')
            Line = $lineNo
        }
    }
    return $entries
}

function Get-CoreFiles {
    param([string]$ProjectRoot)
    $coreRoot = Join-Path $ProjectRoot 'core'
    if (-not (Test-Path -LiteralPath $coreRoot -PathType Container)) {
        throw "core/-Verzeichnis fehlt: $coreRoot"
    }
    $files = Get-ChildItem -LiteralPath $coreRoot -Recurse -File -Force |
        Where-Object {
            $relative = $_.FullName.Substring($ProjectRoot.Length).TrimStart('\', '/').Replace('\', '/')
            # Build-Ausgaben und Arbeitskopien des Toolchains gehoeren nicht zum Quellstand.
            -not ($relative -match '(^|/)(build|\.gradle|\.idea|out)/')
        }
    return $files
}

function Get-RelativeForwardPath {
    param([string]$Base, [string]$FullName)
    return $FullName.Substring($Base.Length).TrimStart('\', '/').Replace('\', '/')
}

function New-Manifest {
    param([string]$ProjectRoot, [string]$ManifestPath, [string[]]$Excluded)
    $excludedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($item in $Excluded) { $null = $excludedSet.Add($item.Replace('\', '/')) }
    $files = Get-CoreFiles -ProjectRoot $ProjectRoot | Sort-Object FullName
    $lines = New-Object System.Collections.Generic.List[string]
    $written = 0
    foreach ($file in $files) {
        $relative = Get-RelativeForwardPath -Base $ProjectRoot -FullName $file.FullName
        if ($excludedSet.Contains($relative)) { continue }
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add("$hash  $relative")
        $written++
    }
    # Bewusst LF und UTF-8 ohne BOM: identisch zum bisherigen Manifestformat.
    [System.IO.File]::WriteAllText($ManifestPath, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-Status "Manifest neu erzeugt: $ManifestPath ($written Dateien)." 'Yellow'
    Write-Status 'Hinweis: Neuimport nur zusammen mit aktualisierter core/PROVENANCE.md zulaessig.' 'Yellow'
    Exit-With 0 'GENERIERT'
}

try {
    $projectRoot = Get-ProjectRoot -Explicit $Root
} catch {
    Write-Host "FEHLER: Projektwurzel nicht aufloesbar: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

if (-not (Test-Path -LiteralPath $projectRoot -PathType Container)) {
    Write-Host "FEHLER: Projektwurzel existiert nicht: $projectRoot" -ForegroundColor Red
    exit 2
}

$manifestPath = if ([System.IO.Path]::IsPathRooted($Manifest)) { $Manifest } else { Join-Path $projectRoot $Manifest }

if ($Generate) {
    try {
        New-Manifest -ProjectRoot $projectRoot -ManifestPath $manifestPath -Excluded $AllowExtra
    } catch {
        Write-Host "FEHLER: Manifest konnte nicht erzeugt werden: $($_.Exception.Message)" -ForegroundColor Red
        exit 2
    }
}

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    Write-Host "FEHLER: Manifest fehlt: $manifestPath" -ForegroundColor Red
    exit 2
}
if ((Get-Item -LiteralPath $manifestPath).Length -eq 0) {
    Write-Host "FEHLER: Manifest ist leer: $manifestPath" -ForegroundColor Red
    exit 2
}

try {
    $entries = Get-ManifestEntries -Path $manifestPath
    $coreFiles = Get-CoreFiles -ProjectRoot $projectRoot
} catch {
    Write-Host "FEHLER: Inventar nicht lesbar: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

if ($entries.Count -eq 0) {
    Write-Host 'FEHLER: Manifest enthaelt keine Eintraege.' -ForegroundColor Red
    exit 2
}

$mismatches = New-Object System.Collections.Generic.List[object]
$missing = New-Object System.Collections.Generic.List[object]
$manifestPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)

Write-Status "Quelle : $manifestPath"
Write-Status "Ziel   : $projectRoot\core"
Write-Status "Eintraege: $($entries.Count)"
Write-Status ''

foreach ($entry in $entries) {
    $null = $manifestPaths.Add($entry.Path)
    $full = Join-Path $projectRoot $entry.Path
    $resolvedFull = $null
    try {
        $resolvedFull = (Resolve-Path -LiteralPath $full -ErrorAction Stop).Path
    } catch {
        $missing.Add($entry) | Out-Null
        continue
    }
    # Pfad-Ausbruch ausserhalb der Projektwurzel ist ein Manifestfehler, kein Dateizustand.
    $normalizedRoot = (Resolve-Path -LiteralPath $projectRoot).Path.TrimEnd('\', '/')
    if (-not ($resolvedFull.StartsWith($normalizedRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase))) {
        Write-Host "FEHLER: Manifestpfad verlaesst die Projektwurzel: $($entry.Path)" -ForegroundColor Red
        exit 2
    }
    if (-not (Test-Path -LiteralPath $resolvedFull -PathType Leaf)) {
        $missing.Add($entry) | Out-Null
        continue
    }
    $actual = (Get-FileHash -LiteralPath $resolvedFull -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.Hash) {
        $mismatches.Add([pscustomobject]@{ Path = $entry.Path; Expected = $entry.Hash; Actual = $actual }) | Out-Null
    }
}

$extras = @()
$documentedExtras = @()
$allowedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
foreach ($item in $AllowExtra) { $null = $allowedSet.Add($item.Replace('\', '/')) }
foreach ($file in $coreFiles) {
    $relative = Get-RelativeForwardPath -Base $projectRoot -FullName $file.FullName
    if (-not $manifestPaths.Contains($relative)) {
        if (-not $Strict -and $allowedSet.Contains($relative)) {
            $documentedExtras += $relative
        } else {
            $extras += $relative
        }
    }
}

foreach ($item in $mismatches) {
    Write-Host "MISMATCH  $($item.Path)" -ForegroundColor Red
    Write-Host "          erwartet $($item.Expected)" -ForegroundColor DarkGray
    Write-Host "          erhalten $($item.Actual)" -ForegroundColor DarkGray
}
foreach ($item in $missing) {
    Write-Host "FEHLT     $($item.Path)" -ForegroundColor Red
}
foreach ($extra in $extras) {
    Write-Host "ZUSATZ    $extra" -ForegroundColor Yellow
}
foreach ($extra in $documentedExtras) {
    Write-Host "HINWEIS   $extra (dokumentierte TV-Provenienzdatei, nicht Teil des Mobile-Quellstands)" -ForegroundColor DarkYellow
}

$problems = $mismatches.Count + $missing.Count + $extras.Count
Write-Status ''
if ($problems -eq 0) {
    Write-Status "ERGEBNIS: PASS - $($entries.Count) Dateien byte-identisch zum Manifest." 'Green'
    if ($documentedExtras.Count -gt 0) {
        Write-Status "Hinweis: $($documentedExtras.Count) dokumentierte Zusatzdatei(en) wurden bewusst ignoriert." 'DarkYellow'
    }
    exit 0
}

Write-Status "ERGEBNIS: FAIL - $($mismatches.Count) Mismatch, $($missing.Count) fehlend, $($extras.Count) zusaetzlich." 'Red'
Write-Status 'Release-Blocker: core/ wurde veraendert. Aenderungen gehoeren in den Mobile-Quellstand,' 'Red'
Write-Status 'danach vollstaendiger Neuimport inklusive frischem Manifest (core/PROVENANCE.md).' 'Red'
exit 1
