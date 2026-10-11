//! Shared controller: the SDK launcher owns this process and its inherited I/O.
mod diagnostics;
#[cfg(windows)]
mod launch;
mod pe;
#[cfg(windows)]
mod platform;
mod process_v2;
#[cfg(windows)]
mod symbol_download;
mod symbols;
mod wire_paths;

/// C ABI is deliberately independent of the C++ compiler and engine internals.
/// The caller retains the UTF-16 bundle path throughout this blocking call.
#[no_mangle]
pub unsafe extern "C" fn MwNativeEngineRun(abi: u32, bundle: *const u16, length: usize) -> i32 {
    if abi != 2 || bundle.is_null() || length == 0 || length > 32767 {
        diagnostics::emit(
            "error",
            "engine_abi_or_path",
            "initialize",
            "Invalid engine ABI or bundle path",
            None,
        );
        return 2;
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(
            std::slice::from_raw_parts(bundle, length),
        ));
        match std::panic::catch_unwind(|| process_v2::run(Some(path))) {
            Ok(Ok(())) => 0,
            Ok(Err(error)) => {
                diagnostics::emit("error", "native_engine_error", "run", &error, None);
                2
            }
            Err(_) => {
                diagnostics::emit(
                    "error",
                    "native_engine_panic",
                    "run",
                    "Engine controller panicked",
                    None,
                );
                2
            }
        }
    }
    #[cfg(not(windows))]
    {
        2
    }
}
