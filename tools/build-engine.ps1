param(
    [ValidateSet('x86', 'x64', 'arm64')][string[]]$Architectures = @('x64', 'x86'),
    [Parameter(Mandatory)][string]$BuildRoot,
    [Parameter(Mandatory)][string]$RuntimeDirectory,
    [string]$VsInstallPath,
    [string]$RustToolchain = '1.94.1',
    [switch]$Test
)
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$buildRootAbsolute = [IO.Path]::GetFullPath($BuildRoot)
$runtimeAbsolute = [IO.Path]::GetFullPath($RuntimeDirectory)
if ($buildRootAbsolute -eq $runtimeAbsolute -or
    $runtimeAbsolute.StartsWith($buildRootAbsolute + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'RuntimeDirectory must be a separate deployment directory.'
}
if (-not $VsInstallPath) {
    $vswhere = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Microsoft Visual Studio\Installer\vswhere.exe'
    $VsInstallPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
if (-not $VsInstallPath) { throw 'MSVC Build Tools are required.' }
Import-Module (Join-Path $VsInstallPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
$cmake = Join-Path $VsInstallPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$ctest = Join-Path (Split-Path $cmake) 'ctest.exe'
$cargo = & rustup which --toolchain $RustToolchain cargo
$env:RUSTC = & rustup which --toolchain $RustToolchain rustc
$env:RUSTUP_TOOLCHAIN = $RustToolchain
$env:CARGO_TARGET_DIR = Join-Path $buildRootAbsolute 'rust'
$env:CARGO_INCREMENTAL = '0'
function Invoke-Logged([string]$Executable, [string[]]$Arguments, [string]$Log) {
    & $Executable @Arguments *> $Log
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $Log -Tail 35
        throw "$Executable failed; see $Log"
    }
}
$packageText = Get-Content -LiteralPath (Join-Path $repository 'controller\Cargo.toml') -Raw
$engineVersion = [regex]::Match($packageText, '(?m)^version = "([^"]+)"').Groups[1].Value
if (-not $engineVersion) { throw 'Engine package version is missing.' }
$manifest = @{ schemaVersion = 1; engineVersion = $engineVersion; abiVersion = 2; architectures = @{} }
foreach ($architecture in $Architectures) {
    $build = Join-Path $buildRootAbsolute $architecture
    New-Item -ItemType Directory -Path $build -Force | Out-Null
    Enter-VsDevShell -VsInstallPath $VsInstallPath -SkipAutomaticLocation -DevCmdArguments "-arch=$architecture -host_arch=x64"
    $env:VSLANG = '1033'
    $target = switch ($architecture) { x86 { 'i686-pc-windows-msvc' } x64 { 'x86_64-pc-windows-msvc' } arm64 { 'aarch64-pc-windows-msvc' } }
    $compiler = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $compiler -or (Split-Path (Split-Path $compiler.Source) -Leaf) -ne $architecture) {
        throw "MSVC compiler for $architecture is unavailable; install that Build Tools component."
    }
    Invoke-Logged $cmake @('-S', $repository, '-B', $build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=ON') (Join-Path $build 'configure.log')
    Invoke-Logged $cmake @('--build', $build, '--parallel', '4') (Join-Path $build 'native-build.log')
    Invoke-Logged $cargo @('build','--manifest-path',(Join-Path $repository 'controller\Cargo.toml'),'--locked','--release','--target',$target) (Join-Path $build 'rust-build.log')
    $output = Join-Path $runtimeAbsolute $architecture
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $build 'bin\mw-native-agent.dll') -Destination $output
    Copy-Item -LiteralPath (Join-Path $env:CARGO_TARGET_DIR "$target\release\companion.exe") -Destination $output
    Copy-Item -LiteralPath (Join-Path $env:CARGO_TARGET_DIR "$target\release\mw_native_runtime.dll") -Destination (Join-Path $output 'mw-native-runtime.dll')
    Invoke-Logged $cmake @('--install',$build,'--prefix',(Join-Path $runtimeAbsolute 'sdk')) (Join-Path $build 'sdk-install.log')
    if ($Test) {
        $consumer = Join-Path $build 'sdk-consumer'
        Invoke-Logged $cmake @('-S',(Join-Path $repository 'tests\sdk-consumer'),'-B',$consumer,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',"-DCMAKE_PREFIX_PATH=$(Join-Path $runtimeAbsolute 'sdk')") (Join-Path $build 'sdk-consumer-configure.log')
        Invoke-Logged $cmake @('--build',$consumer) (Join-Path $build 'sdk-consumer-build.log')
        $example = Join-Path $build 'sdk-example'
        Invoke-Logged $cmake @('-S',(Join-Path $runtimeAbsolute 'sdk\examples\settings-hook'),'-B',$example,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',"-DCMAKE_PREFIX_PATH=$(Join-Path $runtimeAbsolute 'sdk')") (Join-Path $build 'sdk-example-configure.log')
        Invoke-Logged $cmake @('--build',$example,'--parallel','4') (Join-Path $build 'sdk-example-build.log')
    }
    Copy-Item -LiteralPath (Join-Path $build 'bin\notices') -Destination $output -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $build 'bin\THIRD_PARTY_NOTICES.md') -Destination $output
    Copy-Item -LiteralPath (Join-Path $repository 'LICENSE') -Destination $output
    $manifest.architectures[$architecture] = @{
        companionSha256 = (Get-FileHash -LiteralPath (Join-Path $output 'companion.exe')).Hash.ToLowerInvariant()
        agentSha256 = (Get-FileHash -LiteralPath (Join-Path $output 'mw-native-agent.dll')).Hash.ToLowerInvariant()
        controllerSha256 = (Get-FileHash -LiteralPath (Join-Path $output 'mw-native-runtime.dll')).Hash.ToLowerInvariant()
    }
    if ($Test) {
        $nativeOs = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
        if ($architecture -eq 'arm64' -and $nativeOs -ne 'arm64') {
            Write-Host 'ARM64 compile/package succeeded; execution requires ARM64 hardware.'
        } else {
            Invoke-Logged $ctest @('--test-dir',$build,'--output-on-failure') (Join-Path $build 'ctest.log')
            Invoke-Logged $cargo @('test','--manifest-path',(Join-Path $repository 'controller\Cargo.toml'),'--locked','--target',$target) (Join-Path $build 'rust-tests.log')
        }
    }
    Write-Host "Built $architecture into $output"
}
$sdkRoot = Join-Path $runtimeAbsolute 'sdk'
$sdkFiles = @{}
Get-ChildItem -LiteralPath $sdkRoot -File -Recurse | Where-Object Name -ne 'sdk-manifest.json' | ForEach-Object {
    $relative = [IO.Path]::GetRelativePath($sdkRoot, $_.FullName).Replace('\','/')
    $sdkFiles[$relative] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $sdkRoot 'sdk-manifest.json'),
    (@{schemaVersion=1; engineVersion=$engineVersion; abiVersion=2; files=$sdkFiles} | ConvertTo-Json -Depth 8),
    [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $runtimeAbsolute 'engine-manifest.json'),
    ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath (Join-Path $repository 'LICENSE'),(Join-Path $repository 'THIRD_PARTY_NOTICES.md') -Destination $runtimeAbsolute
