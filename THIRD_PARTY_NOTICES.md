# Third-party notices

This repository uses the following third-party components. The native build copies the corresponding upstream license text into `bin/notices` without editing it.

- MinHook-Detours, pinned to commit `e7d5427ede9e658f1810e742822fab2936e058da`: see `notices/minhook-detours-LICENSE` in a built bundle.
- SlimDetours and phnt, distributed within that pinned MinHook-Detours source checkout: see `notices/SlimDetours-LICENSE` and `notices/phnt-LICENSE` in a built bundle.
- nlohmann/json 3.12.0: the vendored header is accompanied by its exact MIT license at `third_party/nlohmann/LICENSE.MIT`; a built bundle includes `notices/nlohmann-json-LICENSE.MIT`.
- Rust crates used by the companion are pinned in `controller/Cargo.lock`. Their exact upstream license files are retained under `third_party/rust-licenses/<crate>-<version>/` and copied to `notices/rust-licenses/` in built bundles. The inventory records each locked crate's declared license expression and the included source files; it includes MIT, Apache-2.0, Unicode-3.0, and Unlicense texts where declared.

The engine vendors the source/support tree from the pinned MinHook-Detours commit and authenticates every vendored file and the upstream root license against `third_party/minhook-detours.SHA256SUMS`. `MW_MINHOOK_SOURCE` overrides remain subject to the same complete file-inventory check. The generated compatibility and lifetime patches are constrained by exact source-text assertions in `cmake/prepare_hook_backend.cmake`. This file is an index and does not replace the upstream license texts.
