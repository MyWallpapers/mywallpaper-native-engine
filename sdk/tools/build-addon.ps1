param(
    [Parameter(Mandatory)][string]$ProjectDirectory,
    [ValidateSet('x64','x86','arm64')][string]$Architecture = 'x64',
    [string]$SdkDirectory = (Join-Path $PSScriptRoot '..'),
    [string]$BuildDirectory
)
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path -LiteralPath $ProjectDirectory).ProviderPath
$sdk = (Resolve-Path -LiteralPath $SdkDirectory).ProviderPath
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $project ".native-build\$Architecture" }
$vswhere = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Install MSVC Build Tools.' }
Import-Module (Join-Path $vs 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments "-arch=$Architecture -host_arch=x64"
$cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
& $cmake -S $project -B $BuildDirectory -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=$sdk"
if ($LASTEXITCODE -ne 0) { throw 'Add-on configuration failed.' }
& $cmake --build $BuildDirectory --parallel 4
if ($LASTEXITCODE -ne 0) { throw 'Add-on compilation failed.' }
$target = @{x64='windows-x86_64'; x86='windows-x86'; arm64='windows-arm64'}[$Architecture]
$output = Join-Path $project "native\out\$target"
New-Item -ItemType Directory -Path $output -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $BuildDirectory "dist\native\$target\addon.dll"),
    (Join-Path $BuildDirectory "dist\native\$target\companion.exe"),
    (Join-Path $BuildDirectory "dist\native\$target\mywallpaper-native-engine.json"),
    (Join-Path $sdk 'LICENSE'),(Join-Path $sdk 'THIRD_PARTY_NOTICES.md') -Destination $output
Copy-Item -LiteralPath (Join-Path $sdk 'notices') -Destination $output -Recurse -Force
Write-Host "Prepared native companion bundle: $output"
