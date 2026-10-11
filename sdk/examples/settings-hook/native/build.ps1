$ErrorActionPreference = 'Stop'
$sdk = $env:MW_NATIVE_SDK_HOME
if (-not $sdk -and $env:MW_NATIVE_ENGINE_HOME) { $sdk = Join-Path $env:MW_NATIVE_ENGINE_HOME 'sdk' }
if (-not $sdk) { $sdk = Join-Path $PSScriptRoot '..\..\..' }
if (-not (Test-Path -LiteralPath (Join-Path $sdk 'tools\build-addon.ps1'))) {
    throw 'Set MW_NATIVE_SDK_HOME to the extracted native SDK.'
}
& (Join-Path $sdk 'tools\build-addon.ps1') -ProjectDirectory (Join-Path $PSScriptRoot '..') -SdkDirectory $sdk
