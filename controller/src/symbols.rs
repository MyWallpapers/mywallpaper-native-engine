//! Exact PDB lookup runs in the exterior process, never in the injected agent.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SymbolRequest {
    pub module: String,
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u32,
    pub machine: u16,
    pub timestamp: u32,
    pub checksum: u32,
    pub pdb_guid: String,
    pub pdb_age: u32,
    pub pdb_file: String,
}

#[derive(Deserialize, Serialize)]
struct CachedSymbol {
    schema: u32,
    identity: SymbolRequest,
    rva: u64,
}

fn cache_key(request: &SymbolRequest) -> String {
    let mut stable = request.clone();
    stable.base = 0; // ASLR must not invalidate an identity-bound relative address.
    stable.path.clear();
    stable.module.clear();
    let bytes = serde_json::to_vec(&stable).expect("a symbol identity is serializable");
    format!("{:x}", Sha256::digest(bytes))
}

fn same_identity(a: &SymbolRequest, b: &SymbolRequest) -> bool {
    cache_key(a) == cache_key(b)
}

pub(crate) fn resolve(
    request: &SymbolRequest,
    cache: &Path,
    search: Option<&str>,
) -> Result<Value, String> {
    let path = cache.join(format!("{}.json", cache_key(request)));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(hit) = serde_json::from_slice::<CachedSymbol>(&bytes) {
            if hit.schema == 1
                && same_identity(request, &hit.identity)
                && hit.rva < request.size as u64
            {
                let mut prepared = serde_json::to_value(request).map_err(|e| e.to_string())?;
                prepared["rva"] = hit.rva.into();
                prepared["cacheHit"] = true.into();
                return Ok(prepared);
            }
        }
    }
    let rva = lookup(request, cache, search)?;
    std::fs::create_dir_all(cache).map_err(|e| format!("cannot create symbol cache: {e}"))?;
    let hit = CachedSymbol {
        schema: 1,
        identity: request.clone(),
        rva,
    };
    let temporary = cache.join(format!("{}.{}.tmp", cache_key(request), std::process::id()));
    std::fs::write(
        &temporary,
        serde_json::to_vec(&hit).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("cannot write symbol cache: {e}"))?;
    // Unique cache keys describe immutable identities. Concurrent identical
    // resolutions may both succeed; a pre-existing valid entry is equivalent.
    if let Err(e) = std::fs::rename(&temporary, &path) {
        let _ = std::fs::remove_file(&temporary);
        if !path.is_file() {
            return Err(format!("cannot commit symbol cache: {e}"));
        }
    }
    let mut prepared = serde_json::to_value(request).map_err(|e| e.to_string())?;
    prepared["rva"] = rva.into();
    prepared["cacheHit"] = false.into();
    Ok(prepared)
}

fn pdb_server_key(request: &SymbolRequest) -> Result<String, String> {
    if request.pdb_guid.len() != 32
        || !request.pdb_guid.bytes().all(|b| b.is_ascii_hexdigit())
        || request.pdb_file.is_empty()
        || request.pdb_file.contains(['/', '\\', ':', '\0'])
        || matches!(request.pdb_file.as_str(), "." | "..")
    {
        return Err("invalid CodeView PDB identity".to_owned());
    }
    let bytes: Vec<_> = (0..16)
        .map(|i| u8::from_str_radix(&request.pdb_guid[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    Ok(order
        .iter()
        .map(|&i| format!("{:02X}", bytes[i]))
        .collect::<String>()
        + &format!("{:X}", request.pdb_age))
}

#[cfg(windows)]
fn lookup(request: &SymbolRequest, cache: &Path, search: Option<&str>) -> Result<u64, String> {
    use std::mem::size_of;
    use std::sync::Mutex;
    use windows::core::{GUID, PCWSTR};
    use windows::Win32::Foundation::{BOOL, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::*;
    use windows::Win32::System::Threading::GetCurrentProcess;
    static DBGHELP: Mutex<()> = Mutex::new(());
    let _serial = DBGHELP
        .lock()
        .map_err(|_| "symbol worker lock was poisoned")?;
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let image = PathBuf::from(&request.path);
    if !image.is_file() {
        return Err("the exact module file is unavailable".to_owned());
    }
    let adjacent = image.parent().unwrap_or(Path::new(".")).to_string_lossy();
    let configured = search.unwrap_or("");
    if configured.contains('\0') || request.name.contains('\0') {
        return Err("symbol path/name contains NUL".to_owned());
    }
    std::fs::create_dir_all(cache).map_err(|e| e.to_string())?;
    let pdb_directory = cache
        .join("pdb")
        .join(&request.pdb_file)
        .join(pdb_server_key(request)?);
    if search.is_none()
        && !image
            .parent()
            .unwrap_or(Path::new("."))
            .join(&request.pdb_file)
            .is_file()
        && !pdb_directory.join(&request.pdb_file).is_file()
    {
        crate::symbol_download::fetch(
            &request.pdb_file,
            &pdb_server_key(request)?,
            &pdb_directory,
        )?;
    }
    let search_path = wide(&format!(
        "{};{};{};{}",
        adjacent,
        cache.display(),
        pdb_directory.display(),
        configured
    ));
    let image_path = wide(&request.path);
    let module_name = wide("mw_symbols");
    let query = wide(&format!("mw_symbols!{}", request.name));
    unsafe {
        let process = GetCurrentProcess();
        let previous_options = SymGetOptions();
        SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
        if let Err(e) = SymInitializeW(process, PCWSTR(search_path.as_ptr()), BOOL(0)) {
            SymSetOptions(previous_options);
            return Err(format!("cannot initialize DbgHelp: {e}"));
        }
        struct Cleanup(HANDLE, u32);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unsafe {
                    let _ = SymCleanup(self.0);
                    SymSetOptions(self.1);
                }
            }
        }
        let _cleanup = Cleanup(process, previous_options);
        let base = SymLoadModuleExW(
            process,
            HANDLE::default(),
            PCWSTR(image_path.as_ptr()),
            PCWSTR(module_name.as_ptr()),
            0x1000_0000,
            request.size,
            None,
            SYM_LOAD_FLAGS(0),
        );
        if base == 0 {
            return Err(format!("cannot load exact PDB for {}", image.display()));
        }
        let mut info = IMAGEHLP_MODULEW64 {
            SizeOfStruct: size_of::<IMAGEHLP_MODULEW64>() as u32,
            ..Default::default()
        };
        SymGetModuleInfoW64(process, base, &mut info)
            .map_err(|e| format!("cannot read PDB identity: {e}"))?;
        let guid_bytes =
            std::slice::from_raw_parts((&info.PdbSig70 as *const GUID).cast::<u8>(), 16);
        let guid = guid_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if info.SymType != SymPdb
            || info.PdbUnmatched.as_bool()
            || info.DbgUnmatched.as_bool()
            || guid != request.pdb_guid
            || info.PdbAge != request.pdb_age
            || info.ImageSize != request.size
            || info.MachineType != request.machine as u32
            || info.TimeDateStamp != request.timestamp
            || info.CheckSum != request.checksum
        {
            return Err("DbgHelp loaded a mismatched module/PDB identity".to_owned());
        }
        let mut symbol = SYMBOL_INFO_PACKAGEW::default();
        symbol.si.SizeOfStruct = size_of::<SYMBOL_INFOW>() as u32;
        symbol.si.MaxNameLen = (symbol.name.len() + 1) as u32;
        SymFromNameW(process, PCWSTR(query.as_ptr()), &mut symbol.si)
            .map_err(|_| format!("exact PDB symbol not found: {}", request.name))?;
        if symbol.si.NameLen as usize > symbol.name.len() {
            return Err("symbol name is too long".to_owned());
        }
        let name = String::from_utf16(std::slice::from_raw_parts(
            symbol.si.Name.as_ptr(),
            symbol.si.NameLen as usize,
        ))
        .map_err(|_| "PDB symbol name is not valid Unicode")?;
        if name != request.name {
            return Err(format!("exact symbol name mismatch: {name}"));
        }
        let rva = symbol
            .si
            .Address
            .checked_sub(base)
            .ok_or("symbol is below module base")?;
        if rva >= request.size as u64 || symbol.si.ModBase != base {
            return Err("symbol is outside its module".to_owned());
        }
        Ok(rva)
    }
}

#[cfg(not(windows))]
fn lookup(_: &SymbolRequest, _: &Path, _: Option<&str>) -> Result<u64, String> {
    Err("PDB resolution requires Windows".to_owned())
}

/// One bounded worker owns all DbgHelp calls. The controller can handle shutdown
/// while a symbol server is slow; it never waits for this thread on process exit.
pub(crate) struct Worker {
    sender: std::sync::mpsc::SyncSender<(u64, Vec<SymbolRequest>, PathBuf, Option<String>)>,
    receiver: std::sync::mpsc::Receiver<(u64, Result<Vec<Value>, String>)>,
}
impl Worker {
    pub(crate) fn new() -> Self {
        let (sender, jobs) =
            std::sync::mpsc::sync_channel::<(u64, Vec<SymbolRequest>, PathBuf, Option<String>)>(8);
        let (results, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            while let Ok((key, requests, cache, search)) = jobs.recv() {
                let prepared = requests
                    .iter()
                    .map(|r| resolve(r, &cache, search.as_deref()))
                    .collect();
                if results.send((key, prepared)).is_err() {
                    break;
                }
            }
        });
        Self { sender, receiver }
    }
    pub(crate) fn submit(
        &self,
        key: u64,
        requests: Vec<SymbolRequest>,
        cache: PathBuf,
        search: Option<String>,
    ) -> Result<(), String> {
        self.sender
            .try_send((key, requests, cache, search))
            .map_err(|e| format!("symbol queue: {e}"))
    }
    pub(crate) fn try_result(&self) -> Option<(u64, Result<Vec<Value>, String>)> {
        self.receiver.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_identity_ignores_aslr_but_not_architecture_or_pdb_age() {
        let a = SymbolRequest {
            module: "m.dll".into(),
            name: "f".into(),
            path: "C:\\m.dll".into(),
            base: 100,
            size: 4096,
            machine: 0x8664,
            timestamp: 7,
            checksum: 9,
            pdb_guid: "000102030405060708090a0b0c0d0e0f".into(),
            pdb_age: 1,
            pdb_file: "m.pdb".into(),
        };
        let mut b = a.clone();
        b.base = 900;
        b.path = "D:\\m.dll".into();
        assert!(same_identity(&a, &b));
        b.pdb_age += 1;
        assert!(!same_identity(&a, &b));
        b = a.clone();
        b.machine = 0xaa64;
        assert!(!same_identity(&a, &b));
        b = a.clone();
        b.name = "other".into();
        assert!(!same_identity(&a, &b));
    }
}
