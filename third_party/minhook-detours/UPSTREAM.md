MinHook-Detours vendor snapshot

Upstream: https://github.com/m417z/minhook-detours
Commit: e7d5427ede9e658f1810e742822fab2936e058da

The `src/` tree and the root `LICENSE` are copied from that exact commit. No repository metadata, CI workflow, or generated binaries are included. `../minhook-detours.SHA256SUMS` authenticates every vendored source/support file and the root license. The engine generates only its narrowly scoped compatibility and lifetime patches into the build directory; it does not edit this upstream snapshot.