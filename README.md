# MyWallpaper Native Engine

This repository contains the first native add-on engine prototype for MyWallpaper. It gives native add-ons a small C++ ABI and gives MyWallpaper a reusable Windows x64 companion that owns injection, settings delivery, a named-pipe session, and target-process cleanup. Add-ons retain ownership of their behavior and UI.

The current backend is pinned MinHook-Detours with a small set of source patches for resident hook reuse and lifecycle metrics. The agent DLL is loaded once into a target process and serves multiple companion sessions concurrently. Each session has its own named pipe, owner process handle, shutdown state, and cleanup scope; the hook registry remains shared inside the agent. A session shutdown stops only add-ons owned by that exact companion PID and creation time.

## Current limits

- The first build supports Windows x64 and MSVC only.
- Add-ons are native C++ DLLs using ABI v1. The engine keeps loaded modules and callback code resident until the target process exits so that entered calls and resident hook bridges cannot jump into unloaded code.
- Each add-on artifact and DLL image is a singleton per target process. A second companion cannot load the same artifact under another layer or settings context; it receives a clear error. ABI v1 has no instance identity, so the same configurator cannot be activated simultaneously for multiple layers in one target process. The Desktop host must explicitly provide one shared device-level principal; otherwise only one layer can activate it at a time.
- Hooks are logical and resident. Stopping an add-on disables its effect and drains cooperative calls, while physical bridges and image pins remain for reuse and process-lifetime safety.
- Repeated starts of the same verified artifact reuse the retained DLL and hook records, including when MyWallpaper materializes that artifact at a new path. A different DLL under the same artifact identity is rejected. Genuinely different add-on DLL versions and retired trampoline regions remain resident until the target process exits, so the prototype does not promise constant memory across an unbounded stream of distinct versions.
- This is an experimental integration for the first MyWallpaper add-on, not a decision to replace every existing native integration or a claim of broad Windows-build compatibility.
- Add-ons run with the user's full process privileges. The engine does not sandbox them.
- Add-on lifecycle callbacks (start, settings_changed, stop) run synchronously under the shared lifecycle lock. The engine cannot preempt arbitrary native callback code. A prompt MW_ERROR_DRAIN_PENDING keeps the agent session available for retries; the companion retries a rejected shutdown once, and owner cleanup retries cooperative draining for up to one second. A callback that never returns can block cleanup and lifecycle operations for every add-on in that target process. Add-ons should keep callbacks bounded and make stop idempotent.

## Build

Use Visual Studio 2022 x64 with CMake and the pinned Rust 1.94.1 toolchain declared in `rust-toolchain.toml`. The repository vendors the required MinHook-Detours source at commit `e7d5427ede9e658f1810e742822fab2936e058da`, so configuration does not depend on network access or future upstream availability. `third_party/minhook-detours.SHA256SUMS` verifies every vendored source/support file and upstream license; an alternate `MW_MINHOOK_SOURCE` path is accepted only if its complete checked file inventory matches that manifest.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
$env:CARGO_INCREMENTAL = '0'
$env:RUSTUP_TOOLCHAIN = '1.94.1-x86_64-pc-windows-msvc'
$env:CARGO_ENCODED_RUSTFLAGS = @('--remap-path-prefix=' + (Get-Location).Path + '=.', '--remap-path-prefix=' + (Join-Path $env:USERPROFILE '.cargo\registry\src') + '=./.cargo/registry', '-C', 'link-arg=/Brepro') -join [char]0x1f
rustup run 1.94.1-x86_64-pc-windows-msvc cargo fmt --check --manifest-path controller/Cargo.toml
rustup run 1.94.1-x86_64-pc-windows-msvc cargo test --locked --manifest-path controller/Cargo.toml
rustup run 1.94.1-x86_64-pc-windows-msvc cargo rustc --locked --release --manifest-path controller/Cargo.toml --target x86_64-pc-windows-msvc --bin companion
```

The public CMake SDK target is `MyWallpaperNativeEngine::SDK`. An add-on can consume it with `add_subdirectory(<engine-repository>/sdk)`; the target supplies the SDK and JSON include directories, C++20, and the Windows Unicode definitions. The engine's tests and native implementation are not built by adding only `sdk/`.

## Companion bundle

Each add-on bundle is self-contained:

```text
companion.exe
mw-native-agent.dll
<addon-library>.dll
mywallpaper-native-engine.json
```

The descriptor identifies the add-on DLL, agent DLL and exact target declaration. Product `addonId` values come from the `process-v2` host (development-session IDs and catalogue UUIDs); they are validated according to that contract and are never compared with a descriptor slug. The companion keeps the exact product ID in opt-in stderr diagnostics and derives its internal resident add-on key from the verified artifact digest. Re-materializing an identical add-on DLL at a new bundle path reuses the already resident image after an exact SHA-256 match. If another bundle has already loaded a byte-identical agent image into the target, the controller reuses that image by SHA-256 identity even when verified bundles have different paths. A different agent binary with the same DLL basename is refused in a target that already has this engine loaded. See [`mywallpaper-native-engine.example.json`](mywallpaper-native-engine.example.json). The companion implements MyWallpaper's existing `process-v2` wire version 5 framing: ordered chunks up to 1 MiB each, with no smaller internal JSON payload cap. Stdout carries wire records only. Set `MW_NATIVE_ENGINE_DIAGNOSTICS=1` to send internal lifecycle and backend responses to stderr for test diagnostics.

The process-v2 init record includes `addonId`, `artifactDigest`, `version`, `targetArchitecture`, `scratchDirectory`, `layerSettings`, and `deviceSettings`. The ABI receives a complete settings snapshot shaped as `{ "layerSettings": ..., "deviceSettings": ..., "scratchDirectory": "..." }`.

## Fixture validation

`tests/run-session-coexistence.ps1` uses a locally built fixture process, not Explorer. It starts two companions with different add-on DLLs against the same process, checks that both effects coexist, rejects one settings update without ending that session, stops one companion and confirms the other effect remains, then rematerializes the first artifact under a different path and verifies byte-identity reuse. It rejects different DLL bytes under the same artifact identity, confirms ABI-invalid and image-invalid callback add-ons are released without a process-lifetime pin, tests cleanup after stdin EOF and forced owner termination (including death immediately after injection during named-pipe startup), then performs 50 restarts using one stable bundle and add-on path. The lower-level CTest suite also measures hook record reuse over repeated stop/start cycles.

## License

The MyWallpaper Native Engine is licensed under the MIT License; see LICENSE. Third-party components retain their own licenses; see THIRD_PARTY_NOTICES.md.

## Third-party notices

See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Redistributable builds include the exact upstream license files beside the native binaries and every registry crate's license text next to `companion.exe`.
