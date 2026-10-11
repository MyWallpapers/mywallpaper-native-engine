# MyWallpaper native add-on SDK

MIT creator SDK for the version 0.2.1 / ABI 2 engine developer preview.
The engine implementation may remain private; this SDK compiles independently.
No engine source or Rust compiler is needed to build an add-on.

The host supplies lifetime, hooking, exact symbol lookup and target discovery.
The add-on owns effects, Windows-specific function signatures, settings and UI.

## Build and test

Install MSVC Build Tools with CMake/Ninja and the appropriate Windows SDK.
Extract the matching engine runtime and this SDK. In PowerShell:

```powershell
$env:MW_NATIVE_ENGINE_HOME = 'C:\Tools\MyWallpaperNativeEngine'
$env:MW_NATIVE_SDK_HOME = 'C:\Tools\MyWallpaperNativeSdk'
Copy-Item "$env:MW_NATIVE_SDK_HOME\examples\settings-hook" 'C:\Projects\MyAddon' -Recurse
& "$env:MW_NATIVE_SDK_HOME\tools\build-addon.ps1" -ProjectDirectory 'C:\Projects\MyAddon'
```

The example produces `addon.dll`, a small `companion.exe` launcher and a JSON
descriptor under `native/out/windows-x86_64`. The launcher loads the shared
`x64/mw-native-runtime.dll` inside its own process: no second controller process
and no engine implementation copied into the add-on. The runtime also contains
the agent and standalone companion CLI. Installation is once per machine/user,
not once per add-on. `MW_NATIVE_ENGINE_HOME` or the descriptor's absolute
`engineDirectory` selects a runtime; the default is
`%LOCALAPPDATA%\MyWallpaper\NativeEngine`.

```powershell
python "$env:MW_NATIVE_SDK_HOME\tools\qualify-addon.py" `
  --engine "$env:MW_NATIVE_ENGINE_HOME" `
  --bundle 'C:\Projects\MyAddon\native\out\windows-x86_64' `
  --fixture 'C:\Projects\MyAddon\.native-build\x64\mw-sdk-fixture.exe' `
  --check-symbol-recovery
```

This starts only the included fixture. It checks settings, rejection, entered
calls, stop/start, owner death, target restart and reports target private bytes.
The example tries an optional internal function, then falls back to an exported
function only after the matching PDB establishes absence. The PDB stays beside
the fixture; do not delete it. The fixture can serve other add-on-owned checks;
integer results are not a general Explorer or XAML compatibility guarantee.

## MyWallpaper integration

The example is a normal `native-v1` add-on with a `process-v2` companion.
`manifest.json` declares device-scoped `enabled` and `delta` settings, which
MyWallpaper renders through its existing settings sidebar. It needs no web page.
`mywallpaper.config.json` invokes the installed SDK builder through the existing
native build declarations. In a copied example repository, set
`MW_NATIVE_SDK_HOME` before invoking the MyWallpaper CLI development command
(`mywallpaper dev --config mywallpaper.config.json`).
`mywallpaper check` validates the prepared project before publication.
Initialize and commit the copied project as its own Git repository before that
check; its root LICENSE and dependency notices are included in the template.
The CLI's prepared native entries remain under `native/out`.

The MyWallpaper launch scope remains x64. The SDK and fixture also support x86
and ARM64 for separate native qualification; that does not add ARM64 Desktop
support. The configured CMake `dist/manifest.json` follows the compiled
architecture; copy that manifest and adjust the native build declaration if
using another host that supports that architecture.

## Lifetime and errors

`MwAddonGetApi` exposes an ABI-versioned C table. Each stable logical identity
gets a context once. Its code, context, call gate and original-pointer storage
must stay alive until the target exits. Release active resources in `stop`, not
the context itself. Never throw exceptions across this ABI.

Call `CallGate::Enter()` before accessing active resources in a detour. Close
the gate in `stop`; return `MW_ERROR_DRAIN_PENDING` if calls remain. The engine
disables the effect and retries cooperative stop. It cannot cancel arbitrary
native callbacks or contain an add-on crash. DLL images and bridges stay
resident; repeated use of one artifact is distinct from loading new versions.

Settings are complete borrowed UTF-8 JSON snapshots. Validate before accepting
them; the engine retains the last accepted snapshot. Acceptance in different
processes is independent. A refused update is not automatically replayed.

`resolve_symbol` uses exact names. Return `MW_ERROR_SYMBOL_PENDING` immediately
when preparation is needed. `MW_ERROR_SYMBOL_NOT_FOUND` permits an add-on-owned
fallback; download, PDB identity and I/O failures do not establish absence.
Preparation failures are reported and retried after five seconds without
stopping unrelated active targets. Retry a refused settings update explicitly
after preparation. Resolving an address does not verify a Windows internal ABI.

Nonfatal diagnostics are UTF-8 JSON lines on stderr (`source`, `schemaVersion`,
`severity`, `code`, `operation`, `message`, optional `targetPid`). Stdout is
reserved for wire v5. MyWallpaper's existing diagnostic tail keeps these
observations separate from fatal wire errors. Its prepared integration renders
these records as readable warnings without a new page or runtime type.

Before changing a shared engine binary, stop its controller processes and
restart targets that retain the old agent. This preview does not promise hot
replacement of resident engine code. Preserve runtime dependency notices.

The optional `tools/install-runtime.ps1 -PackageDirectory C:\Downloads\Runtime`
verifies each architecture's hashes before copying into the default per-user
directory. It refuses to overwrite different engine binaries; choose another
directory and set `MW_NATIVE_ENGINE_HOME` for updates. It does not restart apps,
change permissions or alter a user's persistent environment. Its hashes check
package consistency; the release provider remains the source of trust.
