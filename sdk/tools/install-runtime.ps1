param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [string]$DestinationDirectory = (Join-Path $env:LOCALAPPDATA 'MyWallpaper\NativeEngine')
)
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).ProviderPath
$destination = [IO.Path]::GetFullPath($DestinationDirectory)
if ($destination -eq $package -or $destination.StartsWith($package + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Install into a separate runtime directory.'
}
$manifest = Get-Content -LiteralPath (Join-Path $package 'engine-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $manifest.abiVersion -ne 2) { throw 'Unsupported runtime package.' }
if (-not $manifest.engineVersion -or @($manifest.architectures.PSObject.Properties).Count -eq 0) {
    throw 'Runtime version or architectures are missing.'
}
$existingManifest = Join-Path $destination 'engine-manifest.json'
if (Test-Path -LiteralPath $existingManifest) {
    $installed = Get-Content -LiteralPath $existingManifest -Raw | ConvertFrom-Json
    if ($installed.engineVersion -ne $manifest.engineVersion -or $installed.abiVersion -ne $manifest.abiVersion) {
        throw 'This directory contains another runtime version. Install into a new directory.'
    }
    foreach ($architecture in $installed.architectures.PSObject.Properties) {
        if (-not $manifest.architectures.PSObject.Properties[$architecture.Name]) {
            throw 'The package omits an installed architecture. Use a new directory.'
        }
    }
}
$names = @{companionSha256='companion.exe';agentSha256='mw-native-agent.dll';controllerSha256='mw-native-runtime.dll'}
foreach ($architecture in $manifest.architectures.PSObject.Properties) {
    if ($architecture.Name -notin @('x64','x86','arm64')) { throw 'Unknown runtime architecture.' }
    foreach ($field in $names.Keys) {
        $relative = Join-Path $architecture.Name $names[$field]
        $expected = $architecture.Value.$field
        if ($expected -notmatch '^[a-f0-9]{64}$' -or
            (Get-FileHash -LiteralPath (Join-Path $package $relative)).Hash.ToLowerInvariant() -ne $expected) {
            throw "Runtime package hash mismatch: $relative"
        }
        $existing = Join-Path $destination $relative
        if ((Test-Path -LiteralPath $existing) -and (Get-FileHash -LiteralPath $existing).Hash.ToLowerInvariant() -ne $expected) {
            throw 'This directory contains another runtime. Install to a new directory, select it with MW_NATIVE_ENGINE_HOME, and restart targets that retain the previous agent.'
        }
    }
}
New-Item -ItemType Directory -Path $destination -Force | Out-Null
foreach ($architecture in $manifest.architectures.PSObject.Properties) {
    $target = Join-Path $destination $architecture.Name
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    foreach ($name in $names.Values) {
        if (-not (Test-Path -LiteralPath (Join-Path $target $name))) {
            Copy-Item -LiteralPath (Join-Path $package (Join-Path $architecture.Name $name)) -Destination $target
        }
    }
    Copy-Item -LiteralPath (Join-Path $package "$($architecture.Name)\notices") -Destination $target -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $package "$($architecture.Name)\LICENSE"),
        (Join-Path $package "$($architecture.Name)\THIRD_PARTY_NOTICES.md") -Destination $target
}
Copy-Item -LiteralPath (Join-Path $package 'engine-manifest.json'),(Join-Path $package 'LICENSE'),
    (Join-Path $package 'THIRD_PARTY_NOTICES.md') -Destination $destination
Write-Output $destination
