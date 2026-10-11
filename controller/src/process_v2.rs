use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};

const WIRE_VERSION: u32 = 5;
const MAX_PHYSICAL_CHUNK: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum HostFrame {
    #[serde(rename = "init")]
    Init {
        v: u32,
        #[serde(rename = "addonId")]
        addon_id: String,
        #[serde(rename = "artifactDigest")]
        artifact_digest: String,
        version: String,
        #[serde(rename = "targetArchitecture")]
        target_architecture: String,
        #[serde(rename = "scratchDirectory")]
        scratch_directory: String,
        #[serde(rename = "layerSettings")]
        layer_settings: Value,
        #[serde(rename = "deviceSettings")]
        device_settings: Value,
    },
    #[serde(rename = "settings")]
    Settings {
        v: u32,
        #[serde(rename = "layerSettings")]
        layer_settings: Value,
        #[serde(rename = "deviceSettings")]
        device_settings: Value,
    },
    #[serde(rename = "message")]
    Message {
        v: u32,
        surface: String,
        #[serde(rename = "instanceId")]
        instance_id: String,
        #[serde(rename = "displayIndex")]
        display_index: u32,
        payload: Value,
    },
    #[serde(rename = "shutdown")]
    Shutdown { v: u32 },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleDescriptor {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    addon: DescriptorAddon,
    agent: String,
    target: DescriptorTarget,
    #[serde(rename = "engineDirectory")]
    engine_directory: Option<String>,
    symbols: Option<DescriptorSymbols>,
    launch: Option<DescriptorLaunch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DescriptorLaunch {
    executable: String,
    #[serde(default)]
    arguments: Vec<String>,
    working_directory: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DescriptorSymbols {
    cache_directory: Option<String>,
    search_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorAddon {
    library: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorTarget {
    #[serde(rename = "imageName")]
    image_name: String,
    #[serde(rename = "windowClass")]
    window_class: Option<String>,
    #[serde(default = "single_match", rename = "match")]
    matching: String,
}
fn single_match() -> String {
    "single".to_owned()
}

fn read_chunk<R: Read>(reader: &mut R) -> Result<Option<(u8, Vec<u8>)>, String> {
    let mut header = [0u8; 4];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => unreachable!(),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("cannot read wire header: {error}")),
        }
    }
    reader
        .read_exact(&mut header[1..])
        .map_err(|error| format!("truncated wire header: {error}"))?;
    let raw = u32::from_le_bytes(header);
    let kind = (raw >> 30) as u8;
    let length = (raw & 0x3fff_ffff) as usize;
    if length == 0 || length > MAX_PHYSICAL_CHUNK {
        return Err(format!("invalid physical wire chunk length: {length}"));
    }
    let mut data = Vec::new();
    data.try_reserve_exact(length)
        .map_err(|error| format!("cannot allocate {length}-byte wire chunk: {error}"))?;
    data.resize(length, 0);
    reader
        .read_exact(&mut data)
        .map_err(|error| format!("truncated wire chunk: {error}"))?;
    Ok(Some((kind, data)))
}

fn read_record<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let Some((kind, chunk)) = read_chunk(reader)? else {
        return Ok(None);
    };
    let mut record = match kind {
        0 => return Ok(Some(chunk)),
        1 => chunk,
        2 | 3 => return Err("wire continuation appeared without a start chunk".to_owned()),
        _ => unreachable!(),
    };

    loop {
        let Some((kind, chunk)) = read_chunk(reader)? else {
            return Err("wire stream ended before a multi-chunk record completed".to_owned());
        };
        match kind {
            2 | 3 => {
                record
                    .try_reserve(chunk.len())
                    .map_err(|error| format!("cannot allocate logical wire record: {error}"))?;
                record.extend_from_slice(&chunk);
                if kind == 3 {
                    return Ok(Some(record));
                }
            }
            0 | 1 => return Err("wire record chunks arrived out of order".to_owned()),
            _ => unreachable!(),
        }
    }
}

fn write_record<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("wire JSON record cannot be empty".to_owned());
    }
    let chunks = bytes.chunks(MAX_PHYSICAL_CHUNK).collect::<Vec<_>>();
    for (index, chunk) in chunks.iter().enumerate() {
        let kind = if chunks.len() == 1 {
            0u32
        } else if index == 0 {
            1u32
        } else if index + 1 == chunks.len() {
            3u32
        } else {
            2u32
        };
        let header = ((kind << 30) | chunk.len() as u32).to_le_bytes();
        writer
            .write_all(&header)
            .and_then(|()| writer.write_all(chunk))
            .map_err(|error| format!("cannot write wire record: {error}"))?;
    }
    writer
        .flush()
        .map_err(|error| format!("cannot flush wire record: {error}"))
}

fn write_json<W: Write>(writer: &mut W, value: &Value) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("cannot encode wire JSON: {error}"))?;
    write_record(writer, &bytes)
}

fn wire_error<W: Write>(writer: &mut W, message: &str, code: &str) {
    let _ = write_json(
        writer,
        &json!({"type":"error","v":WIRE_VERSION,"message":message,"code":code}),
    );
}

fn is_recoverable_active_addon_rejection(response: &Value, addon_id: &str) -> bool {
    response.get("ok") == Some(&Value::Bool(false))
        && matches!(
            response.get("code").and_then(Value::as_u64),
            Some(1 | 4 | 11)
        )
        && response
            .get("addons")
            .and_then(Value::as_array)
            .is_some_and(|addons| {
                addons.iter().any(|addon| {
                    addon.get("addonId").and_then(Value::as_str) == Some(addon_id)
                        && addon.get("state").and_then(Value::as_str) == Some("active")
                })
            })
}

fn report_addon_rejection<W: Write>(
    writer: &mut W,
    response: &Value,
    addon_id: &str,
    operation: &str,
    error_code: &str,
    fallback_message: &str,
) {
    if response.get("ok") == Some(&Value::Bool(true)) {
        return;
    }

    let message = response
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or(fallback_message);
    if is_recoverable_active_addon_rejection(response, addon_id) {
        eprintln!(
            "mw-native-engine add-on {addon_id} rejected {operation}; companion remains active: {message}"
        );
    } else {
        wire_error(writer, message, error_code);
    }
}

fn valid_sha256_digest(value: &str) -> Option<&str> {
    let digest = value.strip_prefix("sha256:")?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(digest)
}

fn validate_product_addon_id(value: &str) -> Result<(), String> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
    {
        return Err("init addonId must be non-empty, trimmed, at most 256 UTF-8 bytes, and contain no control characters".to_owned());
    }
    Ok(())
}

fn safe_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(['/', '\\', ':'])
        && name != "."
        && name != ".."
        && std::path::Path::new(name)
            .file_name()
            .and_then(|part| part.to_str())
            == Some(name)
}

fn load_descriptor(
    explicit_bundle: Option<&std::path::Path>,
) -> Result<(BundleDescriptor, std::path::PathBuf), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot find companion executable: {error}"))?;
    let bundle = explicit_bundle
        .or_else(|| executable.parent())
        .ok_or_else(|| "companion executable has no bundle directory".to_owned())?
        .canonicalize()
        .map_err(|error| format!("cannot resolve companion bundle directory: {error}"))?;
    let descriptor_path = bundle.join("mywallpaper-native-engine.json");
    let bytes = std::fs::read(&descriptor_path)
        .map_err(|error| format!("cannot read {}: {error}", descriptor_path.display()))?;
    let descriptor: BundleDescriptor = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid native-engine descriptor: {error}"))?;
    if descriptor.schema_version != 1 && descriptor.schema_version != 2 {
        return Err("unsupported native-engine descriptor schemaVersion".to_owned());
    }
    if !safe_filename(&descriptor.agent)
        || !descriptor.agent.eq_ignore_ascii_case("mw-native-agent.dll")
        || !safe_filename(&descriptor.addon.library)
    {
        return Err("agent must be the bundle-local mw-native-agent.dll and add-on library a bundle-local file name".to_owned());
    }
    if descriptor.target.image_name.is_empty()
        || descriptor.target.image_name.contains(['/', '\\', ':'])
        || descriptor
            .target
            .window_class
            .as_deref()
            .is_some_and(|name| name.is_empty())
    {
        return Err("target declaration is invalid".to_owned());
    }
    if !matches!(descriptor.target.matching.as_str(), "single" | "all") {
        return Err("target match must be single or all".to_owned());
    }
    Ok((descriptor, bundle))
}

fn bundle_file(bundle: &std::path::Path, name: &str) -> Result<std::path::PathBuf, String> {
    let requested = bundle.join(name);
    let path = requested.canonicalize().map_err(|error| {
        format!(
            "cannot resolve bundle file {}: {error}",
            requested.display()
        )
    })?;
    if path.parent() != Some(bundle) || !path.is_file() {
        return Err(format!(
            "bundle file escapes the bundle: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn settings_snapshot(
    layer_settings: Value,
    device_settings: Value,
    scratch_directory: &str,
) -> Value {
    json!({
        "layerSettings": layer_settings,
        "deviceSettings": device_settings,
        "scratchDirectory": scratch_directory,
    })
}

fn diagnostics_enabled() -> bool {
    std::env::var_os("MW_NATIVE_ENGINE_DIAGNOSTICS").is_some_and(|value| value == "1")
}

fn log_diagnostic(stage: &str, response: &Value) {
    if diagnostics_enabled() {
        eprintln!("mw-native-engine {stage}: {response}");
    }
}

#[cfg(windows)]
struct AgentSession {
    pipe: crate::platform::AgentPipeSession,
    addon_id: String,
    next_request_id: u64,
    stopped: bool,
}

#[cfg(windows)]
impl AgentSession {
    fn request(
        &mut self,
        operation: &str,
        mut fields: serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        if self.next_request_id == 0 {
            return Err("internal request identifier exhausted".to_owned());
        }
        fields.insert("id".to_owned(), json!(id));
        fields.insert("operation".to_owned(), json!(operation));
        fields.insert("addonId".to_owned(), json!(self.addon_id));
        let response = self.pipe.request(&Value::Object(fields))?;
        if response.get("id") != Some(&json!(id))
            || response.get("ok").and_then(Value::as_bool).is_none()
        {
            return Err("native agent returned a malformed or mismatched response".to_owned());
        }
        log_diagnostic(operation, &response);
        Ok(response)
    }

    fn request_required(
        &mut self,
        operation: &str,
        fields: serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let response = self.request(operation, fields)?;
        if response.get("ok") == Some(&Value::Bool(true)) {
            Ok(response)
        } else {
            Err(response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("native agent rejected request")
                .to_owned())
        }
    }

    fn shutdown(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        let response = self.request_required("shutdown", serde_json::Map::new())?;
        self.stopped = true;
        log_diagnostic("shutdown-complete", &response);
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for AgentSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(windows)]
struct ManagedSession {
    session: AgentSession,
    active: bool,
    symbol_job: Option<u64>,
}

fn logical_identity(addon_id: &str, scratch: &str, digest: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for component in [addon_id, scratch, digest] {
        hash.update(component.as_bytes());
        hash.update([0]);
    }
    format!("instance-{:x}", hash.finalize())
}

#[cfg(windows)]
fn pending_symbols(
    response: &Value,
    addon_id: &str,
) -> Result<Vec<crate::symbols::SymbolRequest>, String> {
    let requests = response["addons"]
        .as_array()
        .and_then(|addons| {
            addons
                .iter()
                .find(|a| a["addonId"].as_str() == Some(addon_id))
        })
        .and_then(|addon| addon["pendingSymbols"].as_array());
    requests.map_or(Ok(Vec::new()), |requests| {
        requests
            .iter()
            .map(|r| {
                serde_json::from_value(r.clone())
                    .map_err(|e| format!("invalid symbol request: {e}"))
            })
            .collect()
    })
}

#[cfg(windows)]
fn queue_symbols(
    managed: &mut ManagedSession,
    response: &Value,
    worker: &crate::symbols::Worker,
    cache: &std::path::Path,
    search: Option<&str>,
    next_job: &mut u64,
) -> Result<(), String> {
    if managed.symbol_job.is_some() {
        return Ok(());
    }
    let requests = pending_symbols(response, &managed.session.addon_id)?;
    if !requests.is_empty() {
        *next_job = next_job
            .checked_add(1)
            .ok_or("symbol job identifier exhausted")?;
        worker.submit(
            *next_job,
            requests,
            cache.to_path_buf(),
            search.map(str::to_owned),
        )?;
        managed.symbol_job = Some(*next_job);
    }
    Ok(())
}

#[cfg(windows)]
fn activated(response: &Value, before_entrypoint: bool) -> Result<bool, String> {
    if response["ok"] == true {
        return Ok(true);
    }
    if before_entrypoint && response["code"].as_u64() == Some(4) {
        return Err("early add-on requires a module that loads after the entrypoint".to_owned());
    }
    if matches!(response["code"].as_u64(), Some(4 | 11)) {
        return Ok(false);
    }
    Err(response["error"]
        .as_str()
        .unwrap_or("native activation failed")
        .to_owned())
}

#[cfg(windows)]
fn run_after_init<W: Write>(
    init: HostFrame,
    input: std::sync::mpsc::Receiver<Result<Option<Vec<u8>>, String>>,
    writer: &mut W,
    explicit_bundle: Option<&std::path::Path>,
) -> Result<(), String> {
    use std::collections::BTreeMap;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};
    let HostFrame::Init {
        v,
        addon_id,
        artifact_digest,
        version,
        target_architecture,
        scratch_directory,
        layer_settings,
        device_settings,
    } = init
    else {
        return Err("the first wire record must be init".to_owned());
    };
    if v != WIRE_VERSION {
        return Err(format!(
            "wire version {v} is unsupported; expected {WIRE_VERSION}"
        ));
    }
    let architecture = match target_architecture.as_str() {
        "windows-x86_64" => "x64",
        "windows-x86" => "x86",
        "windows-arm64" => "arm64",
        _ => return Err("unsupported Windows add-on architecture".to_owned()),
    };
    if version.trim().is_empty() {
        return Err("init version must not be empty".to_owned());
    }
    let digest = valid_sha256_digest(&artifact_digest)
        .ok_or("artifactDigest must be sha256 followed by 64 hex characters")?;
    validate_product_addon_id(&addon_id)?;
    let (descriptor, bundle) = load_descriptor(explicit_bundle)?;
    let addon_path = bundle_file(&bundle, &descriptor.addon.library)?;
    let engine_root = descriptor
        .engine_directory
        .as_ref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("MW_NATIVE_ENGINE_HOME").map(std::path::PathBuf::from));
    let agent_path = if let Some(root) = &engine_root {
        if !root.is_absolute() {
            return Err("engineDirectory must be absolute".to_owned());
        }
        root.join(architecture)
            .join(&descriptor.agent)
            .canonicalize()
            .map_err(|e| format!("shared engine: {e}"))?
    } else {
        bundle_file(&bundle, &descriptor.agent)?
    };
    let symbol_cache = descriptor
        .symbols
        .as_ref()
        .and_then(|s| s.cache_directory.as_ref())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(&scratch_directory))
                .join("MyWallpaper")
                .join("NativeEngine")
                .join("symbols")
        });
    let symbol_search = descriptor
        .symbols
        .as_ref()
        .and_then(|s| s.search_path.as_deref());
    let symbols = crate::symbols::Worker::new();
    let mut next_job = 0;
    let (owner_pid, owner_creation) = crate::platform::current_process_identity()?;
    let identity = logical_identity(&addon_id, &scratch_directory, &digest.to_ascii_lowercase());
    let mut settings = settings_snapshot(layer_settings, device_settings, &scratch_directory);
    let mut sessions: BTreeMap<(u32, u64), ManagedSession> = BTreeMap::new();
    let mut ready = false;
    let mut next_discovery = Instant::now();
    write_json(writer, &json!({"type":"progress","v":WIRE_VERSION}))?;
    let mut launched = if let Some(launch) = &descriptor.launch {
        if architecture != crate::platform::native_architecture() {
            return Err(
                "controlled launch requires the matching architecture companion".to_owned(),
            );
        }
        let executable = std::path::Path::new(&launch.executable);
        if !executable.file_name().is_some_and(|n| {
            n.to_string_lossy()
                .eq_ignore_ascii_case(&descriptor.target.image_name)
        }) {
            return Err("launch executable must match target imageName".to_owned());
        }
        Some(crate::launch::Prepared::create(
            executable,
            &launch.arguments,
            launch
                .working_directory
                .as_deref()
                .map(std::path::Path::new),
        )?)
    } else {
        None
    };
    let launched_identity = launched
        .as_ref()
        .map(|child| crate::platform::identity(child.pid()))
        .transpose()?;
    loop {
        if Instant::now() >= next_discovery {
            next_discovery = Instant::now() + Duration::from_millis(500);
            sessions.retain(|&(pid, creation), session| {
                if crate::platform::process_alive(pid, creation) {
                    true
                } else {
                    session.session.stopped = true;
                    false
                }
            });
            let targets = if let Some(target) = &launched_identity {
                if crate::platform::process_alive(target.pid, target.creation_time) {
                    vec![target.clone()]
                } else {
                    Vec::new()
                }
            } else {
                crate::platform::find_target_processes(
                    &descriptor.target.image_name,
                    descriptor.target.window_class.as_deref(),
                )?
            };
            let targets: Vec<_> = targets
                .into_iter()
                .filter(|t| t.architecture == architecture)
                .collect();
            if descriptor.target.matching == "single" && targets.len() > 1 {
                return Err(
                    "target is ambiguous; use windowClass or explicitly select match=all"
                        .to_owned(),
                );
            }
            for target in targets {
                let key = (target.pid, target.creation_time);
                if sessions.contains_key(&key) {
                    continue;
                }
                let pipe_name = format!(
                    r"\\.\pipe\mw-native-{owner_pid}-{owner_creation}-{}-{}",
                    key.0, key.1
                );
                let response = crate::platform::inject_dispatch(
                    key.0,
                    key.1,
                    &agent_path,
                    &pipe_name,
                    architecture,
                    engine_root.as_deref(),
                )?;
                log_diagnostic("inject", &response);
                write_json(writer, &json!({"type":"progress","v":WIRE_VERSION}))?;
                let mut managed = ManagedSession {
                    session: AgentSession {
                        pipe: crate::platform::AgentPipeSession::connect(&pipe_name)?,
                        addon_id: identity.clone(),
                        next_request_id: 1,
                        stopped: false,
                    },
                    active: false,
                    symbol_job: None,
                };
                let fields = serde_json::from_value(
                    json!({"path":addon_path.to_string_lossy(),"settings":settings}),
                )
                .unwrap();
                let loaded = managed.session.request("load", fields)?;
                managed.active =
                    activated(&loaded, launched.as_ref().is_some_and(|c| !c.resumed()))?;
                queue_symbols(
                    &mut managed,
                    &loaded,
                    &symbols,
                    &symbol_cache,
                    symbol_search,
                    &mut next_job,
                )?;
                sessions.insert(key, managed);
            }
            for managed in sessions
                .values_mut()
                .filter(|s| !s.active && s.symbol_job.is_none())
            {
                let response = managed
                    .session
                    .request("activate", serde_json::Map::new())?;
                managed.active =
                    activated(&response, launched.as_ref().is_some_and(|c| !c.resumed()))?;
                queue_symbols(
                    managed,
                    &response,
                    &symbols,
                    &symbol_cache,
                    symbol_search,
                    &mut next_job,
                )?;
            }
            if !ready {
                write_json(writer, &json!({"type":"progress","v":WIRE_VERSION}))?;
            }
        }
        while let Some((job, result)) = symbols.try_result() {
            let Some(managed) = sessions.values_mut().find(|s| s.symbol_job == Some(job)) else {
                continue;
            };
            managed.symbol_job = None;
            let prepared = result?;
            let fields = serde_json::from_value(json!({"symbols":prepared})).unwrap();
            managed.session.request_required("prepareSymbols", fields)?;
            if managed.active {
                continue;
            }
            let response = managed
                .session
                .request("activate", serde_json::Map::new())?;
            managed.active = activated(&response, launched.as_ref().is_some_and(|c| !c.resumed()))?;
            queue_symbols(
                managed,
                &response,
                &symbols,
                &symbol_cache,
                symbol_search,
                &mut next_job,
            )?;
        }
        if !ready && !sessions.is_empty() && sessions.values().all(|s| s.active) {
            if let Some(child) = &mut launched {
                child.resume()?;
            }
            write_json(writer, &json!({"type":"ready","v":WIRE_VERSION}))?;
            ready = true;
        }
        let record = match input.recv_timeout(Duration::from_millis(50)) {
            Ok(record) => record?,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => None,
        };
        let Some(bytes) = record else {
            break;
        };
        let frame: HostFrame =
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid host frame: {e}"))?;
        match frame {
            HostFrame::Init { .. } => return Err("init may only appear once".to_owned()),
            HostFrame::Settings {
                v,
                layer_settings,
                device_settings,
            } => {
                if v != WIRE_VERSION {
                    return Err("unsupported settings wire version".to_owned());
                }
                let candidate =
                    settings_snapshot(layer_settings, device_settings, &scratch_directory);
                let mut accepted = true;
                for managed in sessions.values_mut() {
                    let fields = serde_json::from_value(json!({"settings":candidate})).unwrap();
                    let response = managed.session.request("settings", fields)?;
                    accepted &= response["ok"] == true;
                    queue_symbols(
                        managed,
                        &response,
                        &symbols,
                        &symbol_cache,
                        symbol_search,
                        &mut next_job,
                    )?;
                    report_addon_rejection(
                        writer,
                        &response,
                        &managed.session.addon_id,
                        "settings",
                        "addon_settings_rejected",
                        "native add-on rejected settings",
                    );
                }
                if accepted {
                    settings = candidate;
                }
            }
            HostFrame::Message {
                v,
                surface,
                instance_id,
                display_index,
                payload,
            } => {
                if v != WIRE_VERSION {
                    return Err("unsupported message wire version".to_owned());
                }
                for managed in sessions.values_mut().filter(|s| s.active) {
                    let fields = serde_json::from_value(json!({"message": {
                        "surface":surface,"instanceId":instance_id,"displayIndex":display_index,"payload":payload
                    }})).unwrap();
                    let response = managed.session.request("message", fields)?;
                    queue_symbols(
                        managed,
                        &response,
                        &symbols,
                        &symbol_cache,
                        symbol_search,
                        &mut next_job,
                    )?;
                    report_addon_rejection(
                        writer,
                        &response,
                        &managed.session.addon_id,
                        "message",
                        "addon_message_rejected",
                        "native add-on rejected message",
                    );
                }
            }
            HostFrame::Shutdown { v } => {
                if v != WIRE_VERSION {
                    return Err("unsupported shutdown wire version".to_owned());
                }
                break;
            }
        }
    }
    for ((pid, creation), managed) in &mut sessions {
        if crate::platform::process_alive(*pid, *creation) {
            managed.session.shutdown()?;
        } else {
            managed.session.stopped = true;
        }
    }
    Ok(())
}

pub fn run(explicit_bundle: Option<std::path::PathBuf>) -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin;
    let mut writer = stdout.lock();
    let first = match read_record(&mut reader) {
        Ok(Some(record)) => record,
        Ok(None) => return Err("wire stream ended before init".to_owned()),
        Err(error) => {
            wire_error(&mut writer, &error, "invalid_wire");
            return Err(error);
        }
    };
    let text = match std::str::from_utf8(&first) {
        Ok(text) => text,
        Err(error) => {
            let message = format!("init record is not UTF-8: {error}");
            wire_error(&mut writer, &message, "invalid_wire");
            return Err(message);
        }
    };
    let init: HostFrame = match serde_json::from_str(text) {
        Ok(frame) => frame,
        Err(error) => {
            let message = format!("invalid init frame: {error}");
            wire_error(&mut writer, &message, "invalid_init");
            return Err(message);
        }
    };
    #[cfg(windows)]
    let result = {
        let (send, input) = std::sync::mpsc::sync_channel(32);
        std::thread::spawn(move || loop {
            let record = read_record(&mut reader);
            let done = !matches!(&record, Ok(Some(_)));
            if send.send(record).is_err() || done {
                break;
            }
        });
        run_after_init(init, input, &mut writer, explicit_bundle.as_deref())
    };
    #[cfg(not(windows))]
    let result = {
        let _ = init;
        Err("the native companion requires Windows".to_owned())
    };
    if let Err(error) = &result {
        wire_error(&mut writer, error, "native_engine_error");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(kind: u32, bytes: &[u8]) -> Vec<u8> {
        let mut output = ((kind << 30) | bytes.len() as u32).to_le_bytes().to_vec();
        output.extend_from_slice(bytes);
        output
    }

    #[test]
    fn reads_single_and_ordered_multi_chunk_records() {
        let mut bytes = frame(0, b"one");
        bytes.extend(frame(1, b"two-"));
        bytes.extend(frame(2, b"part-"));
        bytes.extend(frame(3, b"three"));
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_record(&mut reader).unwrap().unwrap(), b"one");
        assert_eq!(
            read_record(&mut reader).unwrap().unwrap(),
            b"two-part-three"
        );
        assert!(read_record(&mut reader).unwrap().is_none());
    }

    #[test]
    fn rejects_invalid_chunk_orders_and_truncated_records() {
        let mut reader = Cursor::new(frame(2, b"bad"));
        assert!(read_record(&mut reader).is_err());
        let mut bytes = frame(1, b"start");
        bytes.extend(frame(0, b"unexpected"));
        assert!(read_record(&mut Cursor::new(bytes)).is_err());
        assert!(read_record(&mut Cursor::new(frame(1, b"start"))).is_err());
    }

    #[test]
    fn validates_digest_and_bundle_file_names() {
        assert!(valid_sha256_digest(&format!("sha256:{}", "a".repeat(64))).is_some());
        assert!(valid_sha256_digest("sha256:short").is_none());
        assert!(safe_filename("addon.dll"));
        assert!(!safe_filename("../addon.dll"));
        assert!(!safe_filename("C:\\addon.dll"));
    }

    #[test]
    fn accepts_product_catalogue_and_development_addon_ids() {
        assert!(validate_product_addon_id("01900000-0000-7000-8000-000000000010").is_ok());
        assert!(
            validate_product_addon_id("dev-addon-01900000-0000-7000-8000-000000000010").is_ok()
        );
        assert!(validate_product_addon_id("").is_err());
        assert!(validate_product_addon_id(" addon ").is_err());
        assert!(validate_product_addon_id(&"a".repeat(257)).is_err());
        assert!(validate_product_addon_id("addon\nother").is_err());
    }

    #[test]
    fn descriptor_keeps_binary_identity_out_of_product_addon_id() {
        let descriptor: BundleDescriptor = serde_json::from_value(json!({
            "schemaVersion": 1,
            "addon": { "library": "taskbar.dll" },
            "agent": "mw-native-agent.dll",
            "target": { "imageName": "explorer.exe" }
        }))
        .unwrap();
        assert_eq!(descriptor.addon.library, "taskbar.dll");
    }

    #[test]
    fn active_argument_rejection_does_not_terminate_settings_sequence() {
        let addon_id = "sha256-taskbar";
        let invalid_settings = json!({
            "ok": false,
            "code": 1,
            "error": "add-on settings callback rejected invalid JSON",
            "addons": [{"addonId": addon_id, "state": "active"}]
        });
        let valid_settings = json!({"ok": true, "code": 0});
        let mut wire_output = Vec::new();

        report_addon_rejection(
            &mut wire_output,
            &invalid_settings,
            addon_id,
            "settings",
            "addon_settings_rejected",
            "native add-on rejected settings",
        );
        report_addon_rejection(
            &mut wire_output,
            &valid_settings,
            addon_id,
            "settings",
            "addon_settings_rejected",
            "native add-on rejected settings",
        );

        assert!(wire_output.is_empty());
    }

    #[test]
    fn only_the_active_addons_argument_error_is_nonterminal() {
        let addon_id = "sha256-taskbar";
        let failed_state = json!({
            "ok": false,
            "code": 1,
            "error": "argument rejected",
            "addons": [{"addonId": addon_id, "state": "failed"}]
        });
        let different_addon_active = json!({
            "ok": false,
            "code": 1,
            "error": "argument rejected",
            "addons": [{"addonId": "sha256-other", "state": "active"}]
        });
        let other_code_active = json!({
            "ok": false,
            "code": 7,
            "error": "native failure",
            "addons": [{"addonId": addon_id, "state": "active"}]
        });
        assert!(!is_recoverable_active_addon_rejection(
            &failed_state,
            addon_id
        ));
        assert!(!is_recoverable_active_addon_rejection(
            &different_addon_active,
            addon_id
        ));
        assert!(!is_recoverable_active_addon_rejection(
            &other_code_active,
            addon_id
        ));

        let mut wire_output = Vec::new();
        report_addon_rejection(
            &mut wire_output,
            &failed_state,
            addon_id,
            "settings",
            "addon_settings_rejected",
            "native add-on rejected settings",
        );
        assert!(!wire_output.is_empty());
    }
}
