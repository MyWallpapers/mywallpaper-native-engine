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

fn load_descriptor() -> Result<(BundleDescriptor, std::path::PathBuf), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot find companion executable: {error}"))?;
    let bundle = executable
        .parent()
        .ok_or_else(|| "companion executable has no bundle directory".to_owned())?
        .canonicalize()
        .map_err(|error| format!("cannot resolve companion bundle directory: {error}"))?;
    let descriptor_path = bundle.join("mywallpaper-native-engine.json");
    let bytes = std::fs::read(&descriptor_path)
        .map_err(|error| format!("cannot read {}: {error}", descriptor_path.display()))?;
    let descriptor: BundleDescriptor = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid native-engine descriptor: {error}"))?;
    if descriptor.schema_version != 1 {
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
fn run_after_init<R: Read, W: Write>(
    init: HostFrame,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), String> {
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
    if target_architecture != "windows-x86_64" {
        return Err("this companion supports only windows-x86_64 add-ons".to_owned());
    }
    if version.trim().is_empty() {
        return Err("init version must not be empty".to_owned());
    }
    let digest = valid_sha256_digest(&artifact_digest)
        .ok_or_else(|| "artifactDigest must be sha256 followed by 64 hex characters".to_owned())?;
    let (descriptor, bundle) = load_descriptor()?;
    validate_product_addon_id(&addon_id)?;
    let agent_path = bundle_file(&bundle, &descriptor.agent)?;
    let addon_path = bundle_file(&bundle, &descriptor.addon.library)?;

    if diagnostics_enabled() {
        eprintln!(
            "mw-native-engine identity: productAddonId={:?} artifactDigest=sha256:{} addonLibrary={}",
            addon_id,
            digest.to_ascii_lowercase(),
            descriptor.addon.library,
        );
    }

    write_json(writer, &json!({"type":"progress","v":WIRE_VERSION}))?;
    let (target_pid, target_creation_time) = crate::platform::find_target_process(
        &descriptor.target.image_name,
        descriptor.target.window_class.as_deref(),
    )?;
    let (owner_pid, owner_creation_time) = crate::platform::current_process_identity()?;
    let pipe_name = format!(r"\\.\pipe\mw-native-{}-{}", owner_pid, owner_creation_time);
    let inject_response =
        crate::platform::inject(target_pid, target_creation_time, &agent_path, &pipe_name)?;
    log_diagnostic("inject", &inject_response);
    // Remote thread creation can return before the target's named-pipe worker
    // is ready. Renew the host's idle handshake deadline while connecting.
    write_json(writer, &json!({"type":"progress","v":WIRE_VERSION}))?;
    let mut session = AgentSession {
        pipe: crate::platform::AgentPipeSession::connect(&pipe_name)?,
        addon_id: format!("sha256-{}", digest.to_ascii_lowercase()),
        next_request_id: 1,
        stopped: false,
    };
    let initial_settings = settings_snapshot(layer_settings, device_settings, &scratch_directory);
    let mut load_fields = serde_json::Map::new();
    load_fields.insert("path".to_owned(), json!(addon_path.to_string_lossy()));
    load_fields.insert("settings".to_owned(), initial_settings);
    session.request_required("load", load_fields)?;
    write_json(writer, &json!({"type":"ready","v":WIRE_VERSION}))?;

    while let Some(bytes) = read_record(reader)? {
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| format!("host record is not UTF-8: {error}"))?;
        let frame: HostFrame =
            serde_json::from_str(text).map_err(|error| format!("invalid host frame: {error}"))?;
        match frame {
            HostFrame::Init { .. } => return Err("init may only appear once".to_owned()),
            HostFrame::Settings {
                v,
                layer_settings,
                device_settings,
            } => {
                if v != WIRE_VERSION {
                    return Err("settings frame has an unsupported wire version".to_owned());
                }
                let mut fields = serde_json::Map::new();
                fields.insert(
                    "settings".to_owned(),
                    settings_snapshot(layer_settings, device_settings, &scratch_directory),
                );
                let response = session.request("settings", fields)?;
                if response.get("ok") != Some(&Value::Bool(true)) {
                    let message = response
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("native add-on rejected settings");
                    wire_error(writer, message, "addon_settings_rejected");
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
                    return Err("message frame has an unsupported wire version".to_owned());
                }
                let mut fields = serde_json::Map::new();
                fields.insert(
                    "message".to_owned(),
                    json!({
                        "surface": surface,
                        "instanceId": instance_id,
                        "displayIndex": display_index,
                        "payload": payload,
                    }),
                );
                let response = session.request("message", fields)?;
                if response.get("ok") != Some(&Value::Bool(true)) {
                    let message = response
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("native add-on rejected message");
                    wire_error(writer, message, "addon_message_rejected");
                }
            }
            HostFrame::Shutdown { v } => {
                if v != WIRE_VERSION {
                    return Err("shutdown frame has an unsupported wire version".to_owned());
                }
                session.shutdown()?;
                return Ok(());
            }
        }
    }
    session.shutdown()
}

pub fn run() -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
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
    let result = run_after_init(init, &mut reader, &mut writer);
    #[cfg(not(windows))]
    let result = {
        let _ = init;
        Err("the native companion runs only on Windows x64".to_owned())
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
}
