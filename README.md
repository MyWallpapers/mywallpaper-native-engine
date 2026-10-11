# MyWallpaper Native Engine

A generic native add-on engine for MyWallpaper: a Rust companion manages target
discovery, injection, settings, exact symbols and process ownership; a C++ agent
exposes the native ABI and pinned MinHook-Detours backend. Behavior, effects,
animations and settings semantics belong to add-ons.

The foundation prototype is version 0.2.1 / SDK ABI 2. Existing ABI 1 add-ons
require a port; Windhawk mods are not automatically compatible. This prototype
does not alter the Desktop launch scope or settle the long-term engine choice
in MyWallpaper's decision ledger.

## Core capabilities

- One injected agent image per target, independent companion sessions and
  logical instances. The same verified DLL can serve multiple contexts when its
  author declares `MW_ADDON_INSTANCE_MULTIPLE`; singleton remains available.
- Per-instance lifecycle serialization. Registry locks are released before
  callbacks; a blocked callback does not hold unrelated lifecycle locks.
- Exact PID and process creation-time ownership. Owner death disables its hooks
  before waiting for a blocked callback, without stopping other owners.
- Resident reuse for the same identity/target/detour, including identical DLLs
  rematerialized at another path. Hook chains use aligned atomic original storage.
- Exact PDB symbol preparation outside the target, identity-bound RVA caching,
  common target discovery, multiple matches and reconnection.
- Opt-in owned launch with add-ons active before the PE entrypoint.
- Matching x86, x64 and ARM64 build/package paths. A matching helper performs
  cross-architecture injection while the original companion remains the owner.
- Shared runtime and installed CMake SDK; add-ons need not copy the engine.

The [creator guide](sdk/README.md) includes an independently built example,
MyWallpaper manifest and native build configuration, reusable fixture tests and
runtime installation. The [qualification record](docs/CREATOR-INTEGRATION.md)
describes this isolated implementation and its limits.

There is no visual taskbar framework, sandbox or permission catalogue. Add-ons
are native DLLs with the user's process privileges and can use Windows APIs.

## SDK and lifecycle

Link `MyWallpaperNativeEngine::SDK`, either with
`add_subdirectory(<engine-repository>/sdk)` or the installed package:

```cmake
find_package(MyWallpaperNativeEngine 0.2 CONFIG REQUIRED)
target_link_libraries(my_addon PRIVATE MyWallpaperNativeEngine::SDK)
```

Export `MwAddonGetApi`. ABI 2 supplies `create_instance(host, identity, &context)`
once, followed by `start(context, settings)`, `settings_changed(context, settings)`
and `stop(context)`; `message_received` is optional. Settings are borrowed complete
JSON snapshots. Host and instance contexts stay stable until target process exit.
Stop releases active resources; callbacks must be cooperative and bounded.

Identity includes product add-on ID, stable host scratch directory and artifact
digest, excluding owner PID and temporary bundle path. The host must preserve
scratch identity across restarts and separate simultaneous contexts with distinct
stable scratch directories. Multiple instances do not supply automatic composition
rules for several hooks on the same function.

Stop disables effects and drains cooperative entered calls.
`MW_ERROR_DRAIN_PENDING` preserves resources and logical hook IDs for another
stop attempt; effects are disabled meanwhile. The companion retries cooperative
shutdown for up to one second. Individual native callbacks still have to return.
DLL images, contexts and physical bridges remain resident for lifetime safety.
Repeated restarts of one stable artifact reuse these records. Different versions,
identities or hook targets can still increase retention indefinitely.

Native callbacks cannot be preempted or crash-contained by this engine.
Per-instance locks remove its shared lifecycle bottleneck, but Windows loader
locks, add-on global locks and backend transactions still exist. A callback that
never returns can retain its worker/resources until process exit. Non-image
executable memory remains caller-owned.

## Exact internal symbols

`host->resolve_symbol` uses an exact name, not a closest match. A miss returns
`MW_ERROR_SYMBOL_PENDING` and queues metadata. The exterior companion resolves
the request on one bounded worker, checking architecture, image size, timestamp,
checksum and PDB GUID/age. The agent rechecks loaded identity and executable
section before accepting the RVA. The target never downloads or parses a PDB.

Windows DbgHelp calls within a companion are serialized. Cache keys include
exact symbol and module/PDB identity, ignoring ASLR base and file location.
Without a configured search path, missing PDBs are downloaded via WinHTTP from
Microsoft's HTTPS public symbol server. Explicit `symbols.searchPath`, including
an empty string, uses local/configured lookup instead. Compressed-only server
responses require a matching local PDB or configured symbol path.

Starts awaiting a symbol or module are retried automatically. Pending lookup
during active settings/message callbacks is prepared without reactivating the
instance. Rejected settings do not become the accepted snapshot; explicitly retry
after preparation. Finding an exact address does not establish the function's ABI
or semantic stability across Windows builds; those remain add-on responsibilities.

An identity-verified PDB can establish exact symbol absence and permit an
add-on-owned fallback. Download, identity and I/O failures remain errors, emit
nonfatal diagnostics and retry after five seconds. Successful lookups in a batch
are delivered even when another lookup fails; unrelated effects remain active.

```powershell
companion.exe symbol --module C:/Windows/System32/ntdll.dll --name RtlpAllocateHeap --cache C:/Temp/mw-symbols
```

## Shared deployment and host contract

```text
engine/
  engine-manifest.json
  x64/companion.exe, mw-native-agent.dll, notices/
  x86/companion.exe, mw-native-agent.dll, notices/
  arm64/companion.exe, mw-native-agent.dll, notices/
  sdk/include/, lib/cmake/MyWallpaperNativeEngine/
addon/
  addon.dll
  mywallpaper-native-engine.json
```

Invoke the shared companion with `--bundle ABSOLUTE_ADDON_DIRECTORY`.
Descriptor `engineDirectory`, or `MW_NATIVE_ENGINE_HOME`, selects the runtime.
Bundle-local schema 1 is still accepted; schema 2 adds shared runtime, symbols
and owned launch. See
[`mywallpaper-native-engine.example.json`](mywallpaper-native-engine.example.json).

MyWallpaper's process-v2 wire version 5 is unchanged: ordered chunks up to 1 MiB,
wire records only on stdout. Init includes `addonId`, `artifactDigest`, `version`,
`targetArchitecture`, `scratchDirectory`, `layerSettings` and `deviceSettings`.
Callbacks receive `{layerSettings, deviceSettings, scratchDirectory}`.
Set `MW_NATIVE_ENGINE_DIAGNOSTICS=1` for stderr lifecycle diagnostics.

Target `match` defaults to `single`, or explicitly `all`. Discovery selects
image name, optional window class and required architecture. The manager waits
for absent targets and follows replacements by PID/creation time, replaying the
last accepted settings. Updates across processes are independent callbacks:
some may accept a snapshot another rejects. Global replay advances only when all
current targets accept it; there is no distributed settings transaction.

Optional `launch: {executable, arguments, workingDirectory}` owns one child
and requires a matching companion. A temporary debugger barrier stops its main
thread at the PE entrypoint; injection and activation finish before release.
That child remains the sole target. Startup failure terminates only the
unresumed child; normal shutdown leaves the resumed application running.
This does not intercept arbitrary process creation or precede TLS, DLL
initialization, or code already executed in existing processes.

## Build and qualify

Windows and MSVC Build Tools are required. Rust is pinned to 1.94.1.
Install the Rust target and MSVC component for each requested architecture:

```powershell
./tools/build-engine.ps1 -Architectures x64,x86 -BuildRoot C:/Temp/mw-build -RuntimeDirectory C:/Temp/mw-engine -Test
python ./tests/run-foundation.py --architecture x64 --build C:/Temp/mw-build/x64 --companion C:/Temp/mw-engine/x64/companion.exe --x86-build C:/Temp/mw-build/x86 --x86-companion C:/Temp/mw-engine/x86/companion.exe
```

CTest covers module lifetime, call admission, backend chains and resident reuse.
Rust tests cover command, wire, cache identity and argument contracts. The
foundation runner uses dedicated fixtures for exact private symbols, 1,000
restart cycles, multiple instances, blocked callbacks, owner death, multiple
targets, reconnection, cross-architecture injection and controlled launch.
It never targets Explorer or installed MyWallpaper.
`tests/run-session-coexistence.ps1` retains the original session,
rematerialization and invalid-callback scenarios. CI defines matching
x86/x64/ARM64 execution jobs; configured jobs alone are not proof they passed.

Upstream MinHook-Detours is pinned to
`e7d5427ede9e658f1810e742822fab2936e058da` and authenticated by the complete
`third_party/minhook-detours.SHA256SUMS` inventory. `MW_MINHOOK_SOURCE` must
match it. The reviewed `third_party/patches/resident-hooks.patch` is checked and
applied to a build copy; the upstream tree stays unchanged. Builds do not depend
on a future upstream release or a configure-time network fetch.

See [implementation and qualification evidence](docs/IMPLEMENTATION.md)
for observed results and remaining limits.

## License

MIT; see [LICENSE](LICENSE). Dependencies retain their own licences;
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) indexes retained texts.
Packages include native and Rust dependency notices. The companion calls
Windows-supplied DbgHelp and WinHTTP without redistributing those DLLs.
No Windhawk or ExplorerPatcher source is incorporated.
