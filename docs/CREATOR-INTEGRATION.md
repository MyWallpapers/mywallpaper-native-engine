# Creator integration implementation plan

This is an implementation and qualification record for the isolated prototype,
not a product decision registry. The MyWallpaper ledger remains authoritative.
Baseline: engine `dbb22529d0bf72890dd6cc7a9823c39432b782b5`, MyWallpaper
`299548ebcc20770fd73b10bdffd5f05586fbe126`; ledger SHA-256
`db286d2f07dbf60f8961d480222f688e46cf61ef6ea72238a3a0d62fe17012f3`.
DEC-0012 keeps settings and effects add-on-owned. DEC-0098 covers the MIT SDK.
DEC-0157 still excludes a generic native ecosystem from launch; qualification
of this isolated implementation does not change the launch decision.

## Order and acceptance

1. Complete exact-symbol absence, distinct from PDB/transport failures. Deliver
   successful lookups independently of failures and permit bounded retries.
   Verify optional-symbol fallback and recovery without losing an active effect.
2. Supply an independently compiled, runnable ABI 2 example with settings,
   call admission and cooperative stop. Exercise the installed SDK rather than
   relying on the engine source tree.
3. Export a shared controller DLL and a small SDK launcher using the existing
   MyWallpaper process-v2 contract. Keep one controller process per add-on;
   add-on bundles contain their DLL, descriptor and launcher, not the engine.
4. Emit structured nonfatal diagnostics on stderr. Present them through the
   existing MyWallpaper diagnostic tail without changing wire v5 or adding UI.
5. Ship a reusable fixture and qualification runner in the SDK: settings,
   rejection, stop/start, target restart and memory measurements. Re-run the
   engine regressions and matching x64/x86/ARM64 CI.
6. Export the SDK, example, tools, documentation and notices from the same
   installed package. Verify its inventory excludes private engine sources;
   keep the engine repository private. Publication follows qualification.

Each source change includes reference/caller review in its affected scope.
Existing exports and wire records remain valid; no broad cleanup is planned.

## Results

Implemented in version 0.2.1 / ABI 2, with wire v5 unchanged. The runtime DLL
and standalone CLI compile the same controller modules. Each add-on keeps one
existing process-v2 companion; its SDK launcher loads the shared DLL in that
process. There is no additional broker, settings framework or UI.

Local Windows x64/x86 qualification:

- Native unit tests: 4/4 per architecture; controller unit tests passed.
- Installed SDK compiled independently on x64 and x86, including the launcher.
- Creator fixture: settings, nonfatal rejection, entered-call drain, owner death,
  target restart and PDB-availability recovery passed on both architectures.
  Across 100 cycles of the same artifact and identity, target private bytes grew
  by 4,096 bytes on each architecture. This measures the fixture target; it does
  not bound arbitrary add-on allocations or new artifact generations.
- Foundation regression: exact private symbols, verified positive cache,
  mismatched PDB rejection, deferred stop, partial-start rollback, independent
  contexts, late symbol preparation, multiple targets, target restart,
  x64-to-x86 injection and owned early launch passed. Across 1,000 reuse cycles,
  target private bytes remained 1,220,608; one physical hook record remained.
- MyWallpaper diagnostic decoding: 5/5 tests against the actual isolated source,
  covering fragmented UTF-8, ordinary logs, bounded buffering and redaction.
  The full Windows Desktop library also passed `cargo check --offline --locked`
  using the existing frontend output as a read-only Tauri build input; no
  frontend was built or modified in the active worktree.
- Runtime installer accepted a valid and repeated installation and rejected a
  corrupt package before copying any binaries. All installation tests used
  temporary directories rather than the user's active runtime.

The runnable example exposed a real stop bug: the second draining attempt
treated an already-disabled hook as failure. Cleanup now accepts that backend
status when disabling, preserving handles until cooperative stop finishes.

The SDK source archive is checked against a complete hash inventory and rejects
private controller/agent/backend sources and binaries. Its template includes
root licence, notices, manifest, device settings, native build declaration and
ignored generated outputs. Its manifest and dev configuration passed the
existing MyWallpaper parsers. ARM64 execution and the full packaged creator
path are recorded by the three-architecture CI workflow before publication.

## Impact and retained contracts

Reviewed all callers of exact symbol resolution and worker results in the
controller. Prepared negative results use the agent's existing identity-bound
missing-symbol representation; no second negative disk cache was added.
Per-request results preserve successful resolutions when another request fails.
One bounded symbol worker and the existing discovery loop provide five-second
retries; no new polling service is introduced.

The pipe-path helper moved to one common module; its CLI callers, platform
callers and existing tests remain. CLI-only functions in the common platform
module remain live and are retained. Existing ABI exports, injected agent,
cross-architecture helper, compile-only SDK consumer and old wire records remain
supported. The new exported `MwNativeEngineRun` is called only by the installed
SDK launcher. Effects and Windows internal ABI selection remain add-on-owned.

MyWallpaper changes are confined to stderr decoding and its existing diagnostic
tail. Callers of `sanitize` and `append_bounded`, including Windhawk diagnostics,
remain valid. Structured diagnostics do not become fatal stdout wire records.
No public Desktop contract, generated registry, settings schema or launch
decision was changed. Integration remains in an isolated worktree; the active
Desktop and Explorer have not been switched to this prototype.

This qualification establishes prototype behavior, not broad Windows-build,
Explorer/XAML, arbitrary native callback or production release compatibility.
