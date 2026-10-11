param(
    [Parameter(Mandatory = $true)]
    [string]$BuildDirectory,
    [string]$CompanionPath
)

$ErrorActionPreference = 'Stop'
$resolvedBuild = (Resolve-Path -LiteralPath $BuildDirectory).Path
$bin = Join-Path $resolvedBuild 'bin'
$fixturePath = Join-Path $bin 'mw-native-fixture.exe'
$agentPath = Join-Path $bin 'mw-native-agent.dll'
$addonAPath = Join-Path $bin 'mw-native-session-a.dll'
$addonBPath = Join-Path $bin 'mw-native-session-b.dll'
$invalidAddonPath = Join-Path $bin 'mw-native-invalid-addon.dll'
$invalidCallbackAddonPath = Join-Path $bin 'mw-native-invalid-callback-addon.dll'
if (-not $CompanionPath) {
    $CompanionPath = Join-Path $resolvedBuild 'controller\target\x86_64-pc-windows-msvc\release\companion.exe'
    if (-not (Test-Path -LiteralPath $CompanionPath)) {
        $CompanionPath = Join-Path $bin 'companion.exe'
    }
}
$CompanionPath = (Resolve-Path -LiteralPath $CompanionPath).Path
foreach ($required in @($fixturePath, $agentPath, $addonAPath, $addonBPath,
        $invalidAddonPath, $invalidCallbackAddonPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required fixture artifact is missing: $required"
    }
}

function Read-ExactBytes([System.IO.Stream]$Stream, [int]$Count) {
    $bytes = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $readTask = $Stream.ReadAsync($bytes, $offset, $Count - $offset)
        if (-not $readTask.Wait(15000)) { throw 'Timed out reading framed test output.' }
        $read = $readTask.GetAwaiter().GetResult()
        if ($read -le 0) { throw 'Unexpected EOF in framed stream.' }
        $offset += $read
    }
    return ,$bytes
}

function Read-WireRecord([System.IO.Stream]$Stream) {
    $record = [System.IO.MemoryStream]::new()
    $first = $true
    while ($true) {
        $header = Read-ExactBytes $Stream 4
        $raw = [BitConverter]::ToUInt32($header, 0)
        $kind = [int]($raw -shr 30)
        $length = [int]($raw -band 0x3fffffff)
        if ($length -le 0 -or $length -gt 1048576) { throw "Invalid chunk length: $length" }
        $chunk = Read-ExactBytes $Stream $length
        if ($first -and $kind -eq 0) {
            $record.Write($chunk, 0, $chunk.Length)
            break
        }
        if ($first -and $kind -ne 1) { throw 'Record did not begin with a start chunk.' }
        if (-not $first -and $kind -notin @(2, 3)) { throw 'Record chunks arrived out of order.' }
        $record.Write($chunk, 0, $chunk.Length)
        if ($kind -eq 3) { break }
        $first = $false
    }
    $json = [System.Text.Encoding]::UTF8.GetString($record.ToArray())
    $record.Dispose()
    return $json | ConvertFrom-Json
}

function Write-WireRecord([System.IO.Stream]$Stream, $Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 100 -Compress
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $length = [Math]::Min(1048576, $bytes.Length - $offset)
        if ($bytes.Length -le 1048576) { $kind = 0 }
        elseif ($offset -eq 0) { $kind = 1 }
        elseif ($offset + $length -eq $bytes.Length) { $kind = 3 }
        else { $kind = 2 }
        $header = [BitConverter]::GetBytes(([uint32]$kind -shl 30) -bor [uint32]$length)
        $Stream.Write($header, 0, $header.Length)
        $Stream.Write($bytes, $offset, $length)
        $offset += $length
    }
    $Stream.Flush()
}

function Start-CompanionBundle([string]$Root, [string]$Name, [string]$AddonId, [string]$AddonPath,
    [switch]$TamperAddon, [switch]$KillAfterInjectionProgress) {
    $directory = Join-Path $Root $Name
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
        Copy-Item -LiteralPath $CompanionPath -Destination (Join-Path $directory 'companion.exe')
        Copy-Item -LiteralPath $AddonPath -Destination (Join-Path $directory 'addon.dll')
        Copy-Item -LiteralPath $agentPath -Destination (Join-Path $directory 'mw-native-agent.dll')
    }
    if ($TamperAddon) {
        $tamperedPath = Join-Path $directory 'addon.dll'
        $bytes = [System.IO.File]::ReadAllBytes($tamperedPath)
        [Array]::Resize([ref]$bytes, $bytes.Length + 1)
        $bytes[$bytes.Length - 1] = 0x5a
        [System.IO.File]::WriteAllBytes($tamperedPath, $bytes)
    }
    $descriptor = @{
        schemaVersion = 1
        addon = @{ library = 'addon.dll' }
        agent = 'mw-native-agent.dll'
        target = @{ imageName = 'mw-native-fixture.exe' }
    }
    $descriptorJson = ConvertTo-Json -InputObject $descriptor -Depth 10
    [System.IO.File]::WriteAllText((Join-Path $directory 'mywallpaper-native-engine.json'),
        $descriptorJson, [System.Text.UTF8Encoding]::new($false))

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $directory 'companion.exe'
    $start.WorkingDirectory = $directory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['MW_NATIVE_ENGINE_DIAGNOSTICS'] = '1'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "Could not start companion $Name." }
    $stderr = $process.StandardError.ReadToEndAsync()
    $digestAlgorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digestInput = [System.Text.Encoding]::UTF8.GetBytes($AddonId)
        $digest = ([BitConverter]::ToString($digestAlgorithm.ComputeHash($digestInput))).Replace('-', '').ToLowerInvariant()
    } finally { $digestAlgorithm.Dispose() }
    $init = @{
        type = 'init'; v = 5; addonId = $AddonId
        artifactDigest = 'sha256:' + $digest
        version = '0.1.0'; targetArchitecture = 'windows-x86_64'
        scratchDirectory = $Root; layerSettings = @{}; deviceSettings = @{}
    }
    try {
        Write-WireRecord $process.StandardInput.BaseStream $init
        $sawProgress = $false
        $progressCount = 0
        while ($true) {
            $frame = Read-WireRecord $process.StandardOutput.BaseStream
            if ($frame.type -eq 'progress') {
                $sawProgress = $true
                $progressCount++
                if ($KillAfterInjectionProgress -and $progressCount -eq 2) {
                    # The first progress is sent before target discovery; the
                    # second follows successful injection and immediately
                    # precedes the named-pipe connection attempt.
                    $process.Kill()
                    if (-not $process.WaitForExit(10000)) {
                        throw 'Companion did not exit after owner-death injection test.'
                    }
                    return @{ Process = $process; Stderr = $stderr; Directory = $directory }
                }
                continue
            }
            if ($frame.type -eq 'error') { throw "Companion $Name failed: $($frame.message)" }
            if ($frame.type -eq 'ready') { break }
            throw "Unexpected companion frame from ${Name}: $($frame | ConvertTo-Json -Compress)"
        }
        if (-not $sawProgress) { throw "Companion $Name did not report progress before ready." }
        return @{ Process = $process; Stderr = $stderr; Directory = $directory }
    } catch {
        if (-not $process.HasExited -and -not $process.WaitForExit(5000)) {
            $process.Kill()
            $process.WaitForExit(5000) | Out-Null
        }
        $process.Dispose()
        throw
    }
}

function Stop-Companion($Companion) {
    if ($Companion.Process.HasExited) { return }
    Write-WireRecord $Companion.Process.StandardInput.BaseStream @{ type = 'shutdown'; v = 5 }
    if (-not $Companion.Process.WaitForExit(10000)) {
        throw "Companion PID $($Companion.Process.Id) did not exit after shutdown."
    }
    if ($Companion.Process.ExitCode -ne 0) {
        $diagnostic = $Companion.Stderr.GetAwaiter().GetResult()
        throw "Companion exited with $($Companion.Process.ExitCode): $diagnostic"
    }
}

function Invoke-Fixture([string]$PipeSuffix, [string]$Operation) {
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', $PipeSuffix,
        [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(10000)
        $writer = [System.IO.StreamWriter]::new($pipe,
            [System.Text.UTF8Encoding]::new($false), 1024, $true)
        $reader = [System.IO.StreamReader]::new($pipe,
            [System.Text.UTF8Encoding]::new($false), $false, 1024, $true)
        $writer.WriteLine((ConvertTo-Json -Compress @{ id = 1; operation = $Operation }))
        $writer.Flush()
        $line = $reader.ReadLine()
        if (-not $line) { throw 'Fixture returned an empty response.' }
        $response = $line | ConvertFrom-Json
        if (-not $response.ok) { throw "Fixture rejected ${Operation}: $line" }
        return $response
    } finally {
        $pipe.Dispose()
    }
}

function Wait-ForSample([string]$PipeSuffix, [int]$Compute, [int]$Secondary, [int]$TimeoutMilliseconds = 10000) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $sample = Invoke-Fixture $PipeSuffix 'sample'
        if ($sample.value -eq $Compute -and $sample.secondaryValue -eq $Secondary) { return $sample }
        Start-Sleep -Milliseconds 50
    } while ($timer.ElapsedMilliseconds -lt $TimeoutMilliseconds)
    throw "Fixture values never reached ($Compute, $Secondary); last response: $($sample | ConvertTo-Json -Compress)"
}

function Get-StableResourceSnapshot([int]$ProcessId) {
    $previous = $null
    $stableSamples = 0
    for ($sampleIndex = 0; $sampleIndex -lt 20; $sampleIndex++) {
        $current = Get-Process -Id $ProcessId
        if ($null -ne $previous -and $current.Threads.Count -eq $previous.Threads -and
            $current.HandleCount -eq $previous.Handles) {
            $stableSamples++
            if ($stableSamples -ge 3) { return $current }
        } else {
            $stableSamples = 0
        }
        $previous = @{ Threads = $current.Threads.Count; Handles = $current.HandleCount }
        Start-Sleep -Milliseconds 100
    }
    throw 'Fixture process thread and handle counts did not settle after lifecycle warmup.'
}

function Get-AgentModuleCount([int]$ProcessId) {
    $process = Get-Process -Id $ProcessId
    return @($process.Modules | Where-Object { $_.ModuleName -ieq 'mw-native-agent.dll' }).Count
}

function Get-ModuleCount([int]$ProcessId, [string]$ModuleName) {
    $process = Get-Process -Id $ProcessId
    return @($process.Modules | Where-Object { $_.ModuleName -ieq $ModuleName }).Count
}

$stageRoot = Join-Path $resolvedBuild ('.session-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stageRoot | Out-Null
$pipeSuffix = 'mw-engine-fixture-' + [guid]::NewGuid().ToString('N')
$fixture = $null
$sessionA = $null
$sessionB = $null
$forcedA = $null
$eofA = $null
$rematerializedA = $null
$preconnectA = $null
try {
    $fixtureStart = [System.Diagnostics.ProcessStartInfo]::new()
    $fixtureStart.FileName = $fixturePath
    $fixtureStart.Arguments = "--pipe $pipeSuffix --workers 0"
    $fixtureStart.UseShellExecute = $false
    $fixtureStart.CreateNoWindow = $true
    $fixtureStart.RedirectStandardOutput = $true
    $fixtureStart.RedirectStandardError = $true
    $fixture = [System.Diagnostics.Process]::new()
    $fixture.StartInfo = $fixtureStart
    if (-not $fixture.Start()) { throw 'Could not start the native fixture process.' }
    $fixtureReadyLine = $fixture.StandardOutput.ReadLine()
    if (-not $fixtureReadyLine) { throw 'Fixture did not report readiness.' }
    $fixtureReady = $fixtureReadyLine | ConvertFrom-Json
    if ($fixtureReady.pipe -notlike "*\$pipeSuffix") { throw 'Fixture reported an unexpected pipe.' }
    if ((Invoke-Fixture $pipeSuffix 'sample').value -ne 10) { throw 'Fixture baseline is not stable.' }

    $developmentAddonId = 'dev-addon-01900000-0000-7000-8000-000000000010'
    $catalogueAddonId = '01900000-0000-7000-8000-000000000011'
    $sessionA = Start-CompanionBundle $stageRoot 'a' $developmentAddonId $addonAPath
    $sessionB = Start-CompanionBundle $stageRoot 'b' $catalogueAddonId $addonBPath
    Wait-ForSample $pipeSuffix 11 22 | Out-Null
    if ((Get-AgentModuleCount $fixture.Id) -ne 1) {
        throw 'Byte-identical bundles loaded more than one resident agent image into the target.'
    }

    Write-WireRecord $sessionB.Process.StandardInput.BaseStream @{
        type = 'settings'; v = 5; layerSettings = @{}; deviceSettings = @{ reject = $true }
    }
    # Argument rejection is nonterminal and is reported through diagnostics;
    # a wire error would tell the Desktop host to stop the process.
    Start-Sleep -Milliseconds 100
    if ($sessionB.Process.HasExited) { throw 'A rejected settings snapshot terminated its companion session.' }
    Wait-ForSample $pipeSuffix 11 22 | Out-Null

    Stop-Companion $sessionA
    $sessionA.Process.Dispose()
    Wait-ForSample $pipeSuffix 10 22 | Out-Null

    # Desktop may materialize the same verified artifact into a new bundle
    # directory. The engine must match the DLL bytes and reuse its resident
    # image instead of treating the changed path as a different add-on.
    $rematerializedA = Start-CompanionBundle $stageRoot 'a-rematerialized' $developmentAddonId $addonAPath
    Wait-ForSample $pipeSuffix 11 22 | Out-Null
    Stop-Companion $rematerializedA
    $rematerializedA.Process.Dispose()
    Wait-ForSample $pipeSuffix 10 22 | Out-Null

    $tamperedFailure = $null
    try {
        Start-CompanionBundle $stageRoot 'a-tampered' $developmentAddonId $addonAPath -TamperAddon | Out-Null
    } catch {
        $tamperedFailure = $_.Exception.Message
    }
    if ($tamperedFailure -notmatch 'different add-on DLL bytes') {
        throw "A changed DLL under the same artifact identity was not refused: $tamperedFailure"
    }
    Wait-ForSample $pipeSuffix 10 22 | Out-Null

    # An ABI-invalid module must be released without being process-pinned.
    $invalidAbiFailure = $null
    try {
        Start-CompanionBundle $stageRoot 'invalid-abi' '01900000-0000-7000-8000-000000000012' $invalidAddonPath | Out-Null
    } catch {
        $invalidAbiFailure = $_.Exception.Message
    }
    if ($invalidAbiFailure -notmatch 'incompatible or incomplete') {
        throw "Invalid ABI fixture did not fail at validation: $invalidAbiFailure"
    }
    if ((Get-ModuleCount $fixture.Id 'mw-native-invalid-addon.dll') -ne 0) {
        throw 'ABI-invalid add-on DLL remained resident after rejected load.'
    }

    $invalidCallbackFailure = $null
    try {
        Start-CompanionBundle $stageRoot 'invalid-callback' '01900000-0000-7000-8000-000000000013' $invalidCallbackAddonPath | Out-Null
    } catch {
        $invalidCallbackFailure = $_.Exception.Message
    }
    if ($invalidCallbackFailure -notmatch 'callback table entry 3 must point into committed image code') {
        throw "An image-invalid callback pointer was not rejected before pinning: $invalidCallbackFailure"
    }
    if ((Get-ModuleCount $fixture.Id 'mw-native-invalid-callback-addon.dll') -ne 0) {
        throw 'Add-on with invalid callback pointer remained resident after rejected load.'
    }

    # Every following restart uses the same bundle and add-on file path.
    $forcedA = Start-CompanionBundle $stageRoot 'a-rematerialized' $developmentAddonId $addonAPath
    Wait-ForSample $pipeSuffix 11 22 | Out-Null
    $forcedA.Process.Kill()
    if (-not $forcedA.Process.WaitForExit(10000)) { throw 'Forced companion termination did not complete.' }
    Wait-ForSample $pipeSuffix 10 22 | Out-Null

    # Kill the owner after successful injection but before it reports ready.
    # This races the agent's ConnectNamedPipe/ReadFile startup path and must
    # never affect the independent companion B.
    $preconnectA = Start-CompanionBundle $stageRoot 'a-rematerialized' $developmentAddonId $addonAPath -KillAfterInjectionProgress
    if (-not $preconnectA.Process.HasExited) {
        throw 'The pre-connect owner-death companion was expected to be terminated.'
    }
    Wait-ForSample $pipeSuffix 10 22 | Out-Null
    Write-WireRecord $sessionB.Process.StandardInput.BaseStream @{
        type = 'settings'; v = 5; layerSettings = @{}; deviceSettings = @{ reject = $true }
    }
    Start-Sleep -Milliseconds 100
    if ($sessionB.Process.HasExited) {
        throw 'The independent session stopped responding after the other owner died before pipe setup.'
    }

    $eofA = Start-CompanionBundle $stageRoot 'a-rematerialized' $developmentAddonId $addonAPath
    Wait-ForSample $pipeSuffix 11 22 | Out-Null
    $eofA.Process.StandardInput.Close()
    if (-not $eofA.Process.WaitForExit(10000)) { throw 'Companion did not stop after stdin EOF.' }
    if ($eofA.Process.ExitCode -ne 0) {
        $diagnostic = $eofA.Stderr.GetAwaiter().GetResult()
        throw "EOF cleanup exited with $($eofA.Process.ExitCode): $diagnostic"
    }
    $eofA.Process.Dispose()
    Wait-ForSample $pipeSuffix 10 22 | Out-Null

    # Compare restart growth only after the agent, both add-on images, owner
    # monitors, and crash/EOF paths have completed one warmup pass.
    $warmupSnapshot = Get-StableResourceSnapshot $fixture.Id
    $baselineThreads = $warmupSnapshot.Threads.Count
    $baselineHandles = $warmupSnapshot.HandleCount
    $baselinePrivateBytes = $warmupSnapshot.PrivateMemorySize64

    for ($cycle = 1; $cycle -le 50; $cycle++) {
        $cycleSession = Start-CompanionBundle $stageRoot 'a-rematerialized' $developmentAddonId $addonAPath
        Wait-ForSample $pipeSuffix 11 22 | Out-Null
        Stop-Companion $cycleSession
        $cycleSession.Process.Dispose()
        Wait-ForSample $pipeSuffix 10 22 | Out-Null
        $current = Get-Process -Id $fixture.Id
        if ($current.Threads.Count -gt ($baselineThreads + 2) -or
            $current.HandleCount -gt ($baselineHandles + 2)) {
            throw "Target thread/handle count grew after cycle ${cycle}: threads=$($current.Threads.Count) (base $baselineThreads), handles=$($current.HandleCount) (base $baselineHandles)."
        }
        if (($current.PrivateMemorySize64 - $baselinePrivateBytes) -gt 12MB) {
            throw "Target private memory grew by more than 12 MiB after cycle $cycle."
        }
        if ((Get-AgentModuleCount $fixture.Id) -ne 1) {
            throw "Agent image count changed after cycle $cycle."
        }
    }

    Stop-Companion $sessionB
    $rejectionDiagnostic = $sessionB.Stderr.GetAwaiter().GetResult()
    if (($rejectionDiagnostic | Select-String -AllMatches 'rejected settings; companion remains active').Matches.Count -lt 2) {
        throw 'Settings rejection callbacks did not run for both sessions.'
    }
    $sessionB.Process.Dispose()
    Wait-ForSample $pipeSuffix 10 20 | Out-Null
    $final = Get-Process -Id $fixture.Id
    if ($final.Threads.Count -gt ($baselineThreads + 2) -or
        $final.HandleCount -gt ($baselineHandles + 2)) {
        throw "Target thread/handle count did not return near baseline: threads=$($final.Threads.Count) (base $baselineThreads), handles=$($final.HandleCount) (base $baselineHandles)."
    }
    $bDiagnostics = $sessionB.Stderr.GetAwaiter().GetResult()
    if ($bDiagnostics -notmatch '"activeWorkers":2') {
        throw 'The second companion did not observe the first session in the shared agent runtime.'
    }
    [pscustomobject]@{
        passed = $true
        cycles = 50
        fixturePid = $fixture.Id
        baselineThreads = $baselineThreads
        finalThreads = $final.Threads.Count
        baselineHandles = $baselineHandles
        finalHandles = $final.HandleCount
        baselinePrivateBytes = $baselinePrivateBytes
        finalPrivateBytes = $final.PrivateMemorySize64
        concurrentAddons = 2
        ownerDeathRestoredOnlyOwnedAddon = $true
        sameAgentAndAddonPathsReused = $true
    } | ConvertTo-Json -Depth 5
} finally {
    foreach ($companion in @($sessionA, $sessionB, $forcedA, $eofA, $rematerializedA, $preconnectA)) {
        if ($null -ne $companion -and -not $companion.Process.HasExited) {
            try { $companion.Process.Kill(); $companion.Process.WaitForExit(5000) | Out-Null } catch { }
        }
        if ($null -ne $companion) { $companion.Process.Dispose() }
    }
    if ($null -ne $fixture -and -not $fixture.HasExited) {
        try {
            Invoke-Fixture $pipeSuffix 'shutdown' | Out-Null
            $fixture.WaitForExit(3000) | Out-Null
        } catch { }
        if (-not $fixture.HasExited) { $fixture.Kill(); $fixture.WaitForExit(5000) | Out-Null }
        $fixture.Dispose()
    }
    $resolvedStage = [System.IO.Path]::GetFullPath($stageRoot)
    if ($resolvedStage.StartsWith($resolvedBuild + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    } else {
        throw "Refusing to remove staging directory outside build output: $resolvedStage"
    }
}
