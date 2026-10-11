# Native engine foundation implementation

This is an execution checklist for the user-requested prototype work, not a
second product decision ledger. MyWallpaper's decision authority remains
`docs/decisions/decision-ledger.json` (DEC-0012, DEC-0157, DEC-0160).

Baseline: engine `45499b4def7c6ddbb4a964339fd9ab3c2c84e67c`;
MyWallpaper ledger SHA-256
`db286d2f07dbf60f8961d480222f688e46cf61ef6ea72238a3a0d62fe17012f3`.

Work is isolated on `codex/native-engine-foundation`. Do not change the live
Explorer agent, the original checkout, or the main conversation's application
deployment. Native effects and settings semantics remain add-on-owned.

MyWallpaper baseline commit: `299548ebcc20770fd73b10bdffd5f05586fbe126`.
The ledger fingerprint above was rechecked unchanged during qualification.

| Current decision | Classification | Verified relationship to this prototype |
| --- | --- | --- |
| DEC-0012 | Conforme | Core identity/lifetime/routing stays generic; effects and settings remain add-on-owned |
| DEC-0011 | Conforme | Native add-ons stay full-trust; no sandbox or permission catalogue introduced |
| DEC-0157 | Conforme | Isolated prototype and architecture experiments do not add a generic engine ecosystem or ARM64 Desktop to launch |
| DEC-0160 | Question réellement nouvelle | Replacement foundation adds evidence to the open engine choice; it does not ratify a migration or reopen the closed alternative Windhawk licence path |

## Execution order and acceptance

1. Backend: replace configure-time source substitutions with a reviewed,
   versioned patch set. Encapsulate resident routing inside the backend.
   Existing call, module lifetime, chaining, and reuse tests must still pass.
2. SDK and lifecycle: make logical instances explicit and serialize each
   instance independently. One blocked callback must not block unrelated
   instance status, settings, or shutdown. Preserve image and bridge residency
   and owner PID/creation-time binding.
3. Symbols: prepare exact PDB-derived relative addresses outside the target.
   Cache by module identity; never guess a similar name. Exercise private
   non-exported fixture functions, missing symbols, cache reuse, and shutdown.
4. Targets: share discovery and reconnection, handle multiple matching
   processes, and reapply the latest accepted settings after target restart.
5. Controlled early launch: qualify readiness before the application's entry
   point. Do not claim universal interception of arbitrary process creation or
   of TLS/loader initialization.
6. Architecture and distribution: specify matching native binaries and shared
   engine deployment explicitly. Do not silently use a mismatched image or
   claim ARM64 runtime validation on an x64 machine. This does not change the
   Desktop launch scope.
7. Qualification and scoped dead-code review: run meaningful callback,
   coexistence, owner-loss, stop/restart, and memory plateau scenarios against
   dedicated fixtures. Record observed results and remaining limitations.

## Implemented foundation

All seven implementation stages above are complete, including matching ARM64
fixture execution. This qualifies the exercised foundation scenarios, not broad
production support across Windows builds. The GitHub repository was reverified
PRIVATE after qualification on 2026-10-11.

| Stage | Concrete implementation | Acceptance evidence |
| --- | --- | --- |
| Backend | Verified upstream snapshot plus one versioned build-copy patch; policy uses backend structures directly | Existing backend chain/reuse tests pass on x64, x86 and ARM64 |
| Lifecycle | ABI 2 logical contexts, singleton/multiple declaration, independent instance locks, owner-death hook bypass | Same DLL serves two contexts; one blocked callback does not block the other; owner death bypasses the blocked context |
| Symbols | Exact exterior DbgHelp worker, WinHTTP public-server transport, GUID/age-bound RVA cache and agent revalidation | Non-exported fixture function modified; absent name and mismatched PDB rejected; warm offline cache passes |
| Target manager | Image/window/architecture selection, single/all matching, restart tracking and accepted-snapshot replay | Two matching processes, replacement process and rejected-settings replay tests pass |
| Owned launch | Loader-complete PE-entrypoint debugger barrier, matching companion, only the owned child selected | Very first application call already hooked; normal stop restores behavior; another same-image process stays unchanged |
| Distribution | Shared architecture-specific runtime, cross-architecture injection helper with original owner, installed header-only SDK | Local x64-to-x86 injection/owner-loss tests pass; standalone installed-SDK consumers compile for x64, x86 and ARM64 |
| Qualification | Native/Rust suites, fixture integration, private-memory and original session scenarios | Local and matching CI results below; all three architecture jobs passed |

No taskbar rules, styling framework, permissions catalogue, sandbox or second
MyWallpaper settings protocol was added. The process-v2 version 5 host contract
is unchanged. Host integration is explicit shared-companion invocation with
`--bundle`; the original Desktop and ABI 1 taskbar add-on were not changed.

## Local observed results

Host: Windows 11 build 26200, x64; MSVC 19.44 / Build Tools 17.14;
Rust 1.94.1. The tests used dedicated child fixtures, never live Explorer.

| Check | x64 | x86 |
| --- | --- | --- |
| CTest native suites | 4/4 passed | 4/4 passed |
| Rust unit suites | 15/15 passed | 15/15 passed |
| Installed SDK consumer | Compiled | Compiled |
| Foundation integration | Passed, including cross-architecture injection | Passed |
| Same-artifact start/stop cycles after warm-up | 1,000 | 1,000 |
| Private bytes before / after cycles | 1,216,512 / 1,216,512 | 1,433,600 / 1,437,696 |
| Retained hook records before / after | 1 / 1 | 1 / 1 |
| Trampoline region bytes before / after | 65,536 / 65,536 | 65,536 / 65,536 |
| Other instance settings while one callback blocked | 32 ms | 31 ms |

The 4 KiB x86 variation is an observed whole-process private-memory change, not
evidence of an accumulating hook allocation. The assertions verify stable hook
records/trampoline allocation, and these finite workloads do not prove bounded
memory across arbitrary DLL versions, identities or targets.

The retained session suite also passed 50 restarts: two concurrent add-ons,
owner-specific cleanup, byte-identical rematerialization, differing-image
rejection, invalid callback rejection, stdin EOF and abrupt owner termination.
Its target ended with 3 versus 5 baseline threads, 105 versus 110 handles, and
1,138,688 versus 1,208,320 private bytes.

A separate cold download resolved the non-exported `ntdll.dll!RtlpAllocateHeap`
from Microsoft's matching public PDB, followed by a warm offline cache hit.
Observed PDB GUID bytes: `d13ee3cd2ce3e378eca6171c84a5493b`, age 1;
RVA 343,964. This reads module/PDB files and does not hook ntdll or Explorer.

Reproduce with `tools/build-engine.ps1 -Test`, `tests/run-foundation.py` and
`tests/run-session-coexistence.ps1` as described in README. Local evidence was
retained under `C:/Users/rayan/AppData/Local/Temp/mw-native-foundation-package-build`:
architecture `ctest.log`, `rust-tests.log`, `sdk-consumer-build.log`, plus
`foundation-cross.log`, `foundation-x86.log`, and `session-latest.log`.
The real Windows symbol probe is recorded separately in
`C:/Users/rayan/AppData/Local/Temp/mw-native-foundation-build/windows-symbols.log`.

## Matching CI qualification

Qualified source commit: `8ff92fe4a9f6143b78564a9009784e9d192185a9`.
[GitHub run 38128542232](https://github.com/MyWallpapers/mywallpaper-native-engine/actions/runs/38128542232)
completed successfully on 2026-10-11. The three jobs compiled and executed the
native agent, SDK consumer, unit suites and fixture integration. x86 execution
uses a Windows x64 runner; ARM64 execution uses the matching Windows ARM runner.

| Observed CI check | x64 / windows-2025 | x86 / windows-2025 | ARM64 / windows-11-arm |
| --- | --- | --- | --- |
| CTest | 4/4 | 4/4 | 4/4 |
| Rust | 15/15 | 15/15 | 15/15 |
| Installed SDK consumer | Compiled | Compiled | Compiled |
| Foundation integration | Passed | Passed | Passed |
| Private bytes before / after 1,000 cycles | 1,150,976 / 1,150,976 | 1,507,328 / 1,511,424 | 1,245,184 / 1,265,664 |
| Retained hook records before / after | 1 / 1 | 1 / 1 | 1 / 1 |
| Trampoline region bytes before / after | 65,536 / 65,536 | 65,536 / 65,536 | 65,536 / 65,536 |
| Other instance settings while one callback blocked | 31 ms | 16 ms | 29 ms |

All three integrations include deferred stop with valid hook handles, partial
start rollback, companion shutdown retries, cleanup of no-hook resources after
owner loss, late symbol lookup while active, reconnect and owned-entrypoint
activation. The existing 50-cycle session suite also passed in the x64 job.
The measured ARM64 private-byte variation is 20 KiB while hook records and
trampoline allocation remain constant; it does not support a claim of exactly
zero whole-process allocation or unlimited-workload bounded memory.

Downloaded evidence is retained locally under
`C:/Users/rayan/AppData/Local/Temp/mw-native-foundation-ci-38128542232`, with each
architecture's `foundation.json`, build/unit logs and engine manifest. GitHub
artifacts use seven-day retention. Final report-only edits do not change the
qualified code; the source commit above is the reproducible qualification anchor.

## Scoped dead-code and contract review

- Traced resident policy callers in `resident_hooks.cpp`, agent diagnostics and
  backend/reuse tests. Deleted `native/hook_backend_policy.c` only after moving
  its implementations into the reviewed backend patch; exported policy functions
  remain and CMake links the generated implementation.
- Removed the configure-time text-substitution implementation and its private
  structure-size assumption. Full vendor inventory verification remains; patch
  check/application and patch-hash regeneration replace the old substitutions.
- Extracted Windows platform code from the CLI into `platform.rs`. CLI, wire
  manager, remote bootstrap, exact process identity and pipe consumers reference
  the extracted functions; existing CLI operations remain available.
- Traced dynamic `MwAddonGetApi`/`MwAgentStart` lookups, callback validation,
  optional message callback, generated x86 export alias and public SDK exports.
  ABI 2 is an intentional version boundary; ABI 1 is refused, not silently
  interpreted with a different layout.
- Retained process-lifetime pins, identity hashes, backend chain semantics,
  cooperative call gate and original owner-handle transfer. Static non-observation
  was not used to delete unrelated native probe or integration code.
- A saturated symbol job queue defers and retries preparation instead of
  terminating a companion with many matching processes. Its bounded queue and
  successful retry/disconnection behavior are covered by a Rust regression test.
- Traced the no-hook startup/owner-loss path. A successful start is marked active
  before cooperative cleanup so that an empty hook list does not skip the add-on's
  stop callback. A dedicated fixture owns and releases a native event resource
  while its start callback is blocked; its owner-loss regression passes on all
  three architectures.
- Traced normal stop and partial-start rollback with `MW_ERROR_DRAIN_PENDING`.
  Effects are disabled while logical hook IDs remain valid for the stop retry;
  successful cleanup retires those handles. The companion performs bounded
  cooperative retries instead of reporting the first pending drain as fatal.
  Direct-session and process-v2 fixture regressions cover all three paths.
- Updated the original session test's rejection expectation to match the existing
  wire contract: recoverable active settings rejection is an stderr diagnostic,
  not a terminal host error. Added scenario tests for new behavior rather than
  speculative broad refactors.

## Qualification limits and deliberate boundaries

- ARM64 runs on the matching CI machine, not this x64 development host. Its
  owned-entrypoint barrier uses Windows' documented
  [BRK #0xF000](https://learn.microsoft.com/en-us/cpp/intrinsics/debugbreak),
  and that path passes the same runtime fixture as x64 and x86. These finite
  fixture runs do not establish Explorer or all-Windows-build compatibility.
- A prepared exact address does not guarantee the internal function's calling
  convention or behavior. Add-ons maintain their Windows-specific knowledge;
  the core maintains generic discovery, caching and lifecycle mechanisms.
- Entry-point readiness applies only to an owned child and does not precede TLS,
  loader initialization or arbitrary external process creation. A pending module
  unavailable at the held entrypoint fails instead of waiting indefinitely.
- A native callback cannot be forcibly cancelled or isolated from the target.
  Instance locks avoid the engine's global callback lock; they cannot remove
  add-on global locks or Windows loader-lock constraints.
- Stable stop/start plateaus do not remove residency of genuinely new versions.
  Unloading arbitrary callback code safely is not claimed.
- Settings acceptance across different processes is independent; no distributed
  transaction or generic effect-composition policy was introduced.
- The isolated engine branch is not merged into MyWallpaper, and its Desktop
  integration and existing ABI 1 add-ons have not been migrated. That keeps this
  side-conversation work from altering the active application worktree.
