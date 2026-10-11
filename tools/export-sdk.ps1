param(
    [Parameter(Mandatory)][string]$SdkDirectory,
    [Parameter(Mandatory)][string]$ArchivePath
)
$ErrorActionPreference = 'Stop'
$sdk = (Resolve-Path -LiteralPath $SdkDirectory).ProviderPath
$allowedRoots = @('include','lib','share','examples','tools','notices')
$allowedFiles = @('LICENSE','THIRD_PARTY_NOTICES.md','README.md','sdk-manifest.json')
$files = Get-ChildItem -LiteralPath $sdk -File -Recurse
foreach ($file in $files) {
    $relative = [IO.Path]::GetRelativePath($sdk, $file.FullName).Replace('\','/')
    $root = $relative.Split('/')[0]
    if ($root -notin $allowedRoots -and $relative -notin $allowedFiles) {
        throw "Unexpected SDK distribution file: $relative"
    }
    if ($relative -match '(^|/)(target|third_party|minhook-detours|controller|agent\.cpp|resident_hooks\.cpp)(/|$)' -or
        $file.Extension -in @('.rs','.dll','.exe','.pdb')) {
        throw "Private implementation or unexpected binary in source SDK: $relative"
    }
}
$metadata = Get-Content -LiteralPath (Join-Path $sdk 'sdk-manifest.json') -Raw | ConvertFrom-Json
if ($metadata.abiVersion -ne 2 -or -not $metadata.engineVersion) { throw 'SDK version metadata is invalid.' }
foreach ($entry in $metadata.files.PSObject.Properties) {
    $file = Join-Path $sdk $entry.Name
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) {
        throw "SDK inventory mismatch: $($entry.Name)"
    }
}
if (@($files | Where-Object Name -ne 'sdk-manifest.json').Count -ne @($metadata.files.PSObject.Properties).Count) {
    throw 'SDK inventory is incomplete.'
}
Compress-Archive -Path (Join-Path $sdk '*') -DestinationPath $ArchivePath -Force
Write-Host "Exported source SDK $($metadata.engineVersion): $ArchivePath"
