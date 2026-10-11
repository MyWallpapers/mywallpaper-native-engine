use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;
use std::time::Duration;

#[cfg(windows)]
mod launch;
mod pe;
mod process_v2;
#[cfg(windows)]
mod symbol_download;
mod symbols;

const PIPE_IO_TIMEOUT: Duration = Duration::from_secs(10);
const PIPE_NAME_CAPACITY: usize = 192;
const PIPE_PREFIX: &str = r"\\.\pipe\";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Symbol {
        module: PathBuf,
        name: String,
        cache: PathBuf,
        search: Option<String>,
    },
    Identity {
        pid: u32,
    },
    Inject {
        pid: u32,
        creation_time: u64,
        agent: PathBuf,
        pipe: String,
        owner: Option<(u32, u64)>,
    },
    Request {
        pipe: String,
        json: Option<String>,
        file: Option<PathBuf>,
        stdin: bool,
    },
}

fn usage() -> &'static str {
    "Usage:\n  companion --bundle ADDON_DIRECTORY\n  companion identity --pid PID\n  companion inject --pid PID --creation-time FILETIME --agent DLL --pipe NAME [--owner-pid PID --owner-creation-time FILETIME]\n  companion request --pipe NAME (--json JSON | --file PATH | --stdin)\n  companion symbol --module PATH --name EXACT_NAME --cache DIRECTORY [--search-path PATH]"
}

fn parse_options(args: &[String], flags: &[&str]) -> Result<HashMap<String, String>, String> {
    let mut values = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = &args[index];
        if !key.starts_with("--") {
            return Err(format!("Unexpected positional argument: {key}"));
        }
        if values.contains_key(key) {
            return Err(format!("Option supplied more than once: {key}"));
        }
        if flags.contains(&key.as_str()) {
            values.insert(key.clone(), String::new());
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("Missing value for {key}"))?;
        if value.starts_with("--") {
            return Err(format!("Missing value for {key}"));
        }
        values.insert(key.clone(), value.clone());
        index += 2;
    }
    Ok(values)
}

fn required<'a>(options: &'a HashMap<String, String>, key: &str) -> Result<&'a str, String> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("Required option missing: {key}"))
}

fn reject_unknown(options: &HashMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    if let Some(key) = options.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("Unknown option: {key}"));
    }
    Ok(())
}

fn parse_command(args: &[String]) -> Result<Command, String> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(usage().to_owned());
    };
    match verb.as_str() {
        "symbol" => {
            let options = parse_options(rest, &[])?;
            reject_unknown(
                &options,
                &["--module", "--name", "--cache", "--search-path"],
            )?;
            Ok(Command::Symbol {
                module: required(&options, "--module")?.into(),
                name: required(&options, "--name")?.into(),
                cache: required(&options, "--cache")?.into(),
                search: options.get("--search-path").cloned(),
            })
        }
        "identity" => {
            let options = parse_options(rest, &[])?;
            reject_unknown(&options, &["--pid"])?;
            let pid = required(&options, "--pid")?
                .parse::<u32>()
                .map_err(|_| "--pid must be a positive 32-bit integer".to_owned())?;
            if pid == 0 {
                return Err("--pid must be greater than zero".to_owned());
            }
            Ok(Command::Identity { pid })
        }
        "inject" => {
            let options = parse_options(rest, &[])?;
            reject_unknown(
                &options,
                &[
                    "--pid",
                    "--creation-time",
                    "--agent",
                    "--pipe",
                    "--owner-pid",
                    "--owner-creation-time",
                ],
            )?;
            let pid = required(&options, "--pid")?
                .parse::<u32>()
                .map_err(|_| "--pid must be a positive 32-bit integer".to_owned())?;
            if pid == 0 {
                return Err("--pid must be greater than zero".to_owned());
            }
            let creation_time = required(&options, "--creation-time")?
                .parse::<u64>()
                .map_err(|_| "--creation-time must be a decimal FILETIME value".to_owned())?;
            let agent = PathBuf::from(required(&options, "--agent")?);
            if agent.as_os_str().is_empty() {
                return Err("--agent cannot be empty".to_owned());
            }
            let pipe = canonical_pipe_path(required(&options, "--pipe")?)?;
            Ok(Command::Inject {
                pid,
                creation_time,
                agent,
                pipe,
                owner: if options.contains_key("--owner-pid")
                    || options.contains_key("--owner-creation-time")
                {
                    Some((
                        required(&options, "--owner-pid")?
                            .parse()
                            .map_err(|_| "invalid owner PID")?,
                        required(&options, "--owner-creation-time")?
                            .parse()
                            .map_err(|_| "invalid owner creation time")?,
                    ))
                } else {
                    None
                },
            })
        }
        "request" => {
            let options = parse_options(rest, &["--stdin"])?;
            reject_unknown(&options, &["--pipe", "--json", "--file", "--stdin"])?;
            let pipe = canonical_pipe_path(required(&options, "--pipe")?)?;
            let json = options.get("--json").cloned();
            let file = options.get("--file").map(PathBuf::from);
            let stdin = options.contains_key("--stdin");
            if usize::from(json.is_some()) + usize::from(file.is_some()) + usize::from(stdin) != 1 {
                return Err("request requires exactly one of --json, --file, or --stdin".to_owned());
            }
            Ok(Command::Request {
                pipe,
                json,
                file,
                stdin,
            })
        }
        "--help" | "-h" | "help" => Err(usage().to_owned()),
        _ => Err(format!("Unknown command: {verb}\n{}", usage())),
    }
}

fn canonical_pipe_path(name: &str) -> Result<String, String> {
    let suffix = if name
        .get(..PIPE_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PIPE_PREFIX))
    {
        &name[PIPE_PREFIX.len()..]
    } else {
        name
    };
    if suffix.is_empty()
        || suffix.contains(['\\', '/'])
        || suffix.chars().any(|ch| ch.is_control() || ch == ':')
    {
        return Err(
            "--pipe must be a pipe name, optionally prefixed with \\\\.\\pipe\\".to_owned(),
        );
    }
    let full = format!("{PIPE_PREFIX}{suffix}");
    if full.encode_utf16().count() + 1 > PIPE_NAME_CAPACITY {
        return Err(format!(
            "--pipe exceeds the {max}-character bootstrap limit",
            max = PIPE_NAME_CAPACITY - 1
        ));
    }
    Ok(full)
}

fn request_id(value: &Value) -> Result<Value, String> {
    let id = value
        .as_object()
        .and_then(|object| object.get("id"))
        .ok_or_else(|| "request JSON must be an object with an id".to_owned())?;
    match id {
        Value::String(_) | Value::Number(_) => Ok(id.clone()),
        _ => Err("request id must be a string or number".to_owned()),
    }
}

fn validate_response_id(response: &Value, expected_id: &Value) -> Result<(), String> {
    let actual_id =
        request_id(response).map_err(|_| "pipe response is missing a valid id".to_owned())?;
    if &actual_id != expected_id {
        return Err("pipe response id does not match the request id".to_owned());
    }
    if !response
        .as_object()
        .and_then(|object| object.get("ok"))
        .is_some_and(Value::is_boolean)
    {
        return Err("pipe response must include a boolean ok field".to_owned());
    }
    Ok(())
}

fn read_request_json(command: &Command) -> Result<Vec<u8>, String> {
    let bytes = match command {
        Command::Request {
            json: Some(json), ..
        } => json.as_bytes().to_vec(),
        Command::Request {
            file: Some(path), ..
        } => std::fs::read(path).map_err(|error| format!("Cannot read request file: {error}"))?,
        Command::Request { stdin: true, .. } => {
            let mut bytes = Vec::new();
            io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|error| format!("Cannot read request JSON from stdin: {error}"))?;
            bytes
        }
        _ => return Err("internal error: expected request command".to_owned()),
    };
    if bytes.is_empty() {
        return Err("request JSON must not be empty".to_owned());
    }
    Ok(bytes)
}

fn execute(command: Command) -> Result<String, String> {
    match command {
        Command::Symbol {
            module,
            name,
            cache,
            search,
        } => {
            let module = module.canonicalize().map_err(|e| e.to_string())?;
            let bytes = std::fs::read(&module).map_err(|e| e.to_string())?;
            let request = pe::Image::parse(&bytes)?.symbol_request(&module, &name)?;
            serde_json::to_string(&symbols::resolve(&request, &cache, search.as_deref())?)
                .map_err(|e| e.to_string())
        }
        Command::Identity { pid } => {
            let identity = platform::identity(pid)?;
            serde_json::to_string(&identity).map_err(|error| error.to_string())
        }
        Command::Inject {
            pid,
            creation_time,
            agent,
            pipe,
            owner,
        } => {
            let result = if let Some((owner_pid, owner_creation)) = owner {
                platform::inject_for_owner(
                    pid,
                    creation_time,
                    &agent,
                    &pipe,
                    owner_pid,
                    owner_creation,
                )?
            } else {
                platform::inject(pid, creation_time, &agent, &pipe)?
            };
            serde_json::to_string(&result).map_err(|error| error.to_string())
        }
        request @ Command::Request { .. } => {
            let input = read_request_json(&request)?;
            let value: Value = serde_json::from_slice(&input)
                .map_err(|error| format!("invalid request JSON: {error}"))?;
            let id = request_id(&value)?;
            let pipe = match &request {
                Command::Request { pipe, .. } => pipe,
                _ => unreachable!(),
            };
            let response = platform::request(pipe, &value)?;
            validate_response_id(&response, &id)?;
            serde_json::to_string(&response).map_err(|error| error.to_string())
        }
    }
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || (args.first().is_some_and(|a| a == "--bundle") && args.len() == 2) {
        let bundle = args.get(1).map(PathBuf::from);
        if let Err(error) = process_v2::run(bundle) {
            eprintln!("{error}");
            process::exit(2);
        }
        return;
    }
    let result = parse_command(&args).and_then(execute);
    match result {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            process::exit(2);
        }
    }
}

#[cfg(windows)]
pub(crate) mod platform;

#[cfg(not(windows))]
pub(crate) mod platform {
    use serde_json::Value;
    use std::path::Path;

    #[derive(serde::Serialize)]
    pub struct Identity {
        pid: u32,
        #[serde(rename = "creationTime")]
        creation_time: u64,
        architecture: String,
    }

    pub fn identity(_pid: u32) -> Result<Identity, String> {
        Err("this companion only runs on Windows".to_owned())
    }

    pub fn inject(
        _pid: u32,
        _creation_time: u64,
        _agent: &Path,
        _pipe: &str,
    ) -> Result<Value, String> {
        Err("this controller only injects on Windows".to_owned())
    }

    pub fn inject_for_owner(
        pid: u32,
        creation: u64,
        agent: &Path,
        pipe: &str,
        _: u32,
        _: u64,
    ) -> Result<Value, String> {
        inject(pid, creation, agent, pipe)
    }

    pub fn request(_pipe: &str, _request: &Value) -> Result<Value, String> {
        Err("named pipes are only available on Windows".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_cli_requires_positive_pid_and_rejects_extra_options() {
        assert_eq!(
            parse_command(&["identity".into(), "--pid".into(), "47".into()]),
            Ok(Command::Identity { pid: 47 })
        );
        assert!(parse_command(&["identity".into(), "--pid".into(), "0".into()]).is_err());
        assert!(parse_command(&[
            "identity".into(),
            "--pid".into(),
            "47".into(),
            "--force".into(),
        ])
        .is_err());
    }

    #[test]
    fn inject_cli_parses_decimal_creation_time_and_normalizes_pipe() {
        let parsed = parse_command(&[
            "inject".into(),
            "--pid".into(),
            "47".into(),
            "--creation-time".into(),
            "184467".into(),
            "--agent".into(),
            "agent.dll".into(),
            "--pipe".into(),
            "fixture-47".into(),
        ])
        .unwrap();
        assert_eq!(
            parsed,
            Command::Inject {
                pid: 47,
                creation_time: 184467,
                agent: PathBuf::from("agent.dll"),
                pipe: r"\\.\pipe\fixture-47".to_owned(),
                owner: None,
            }
        );
        assert!(parse_command(&[
            "inject".into(),
            "--pid".into(),
            "47".into(),
            "--creation-time".into(),
            "0x10".into(),
            "--agent".into(),
            "agent.dll".into(),
            "--pipe".into(),
            "fixture-47".into(),
        ])
        .is_err());
    }

    #[test]
    fn pipe_name_fits_bootstrap_and_rejects_path_traversal() {
        assert_eq!(
            canonical_pipe_path(r"\\.\pipe\Agent_42").unwrap(),
            r"\\.\pipe\Agent_42"
        );
        assert!(canonical_pipe_path("folder\\pipe").is_err());
        assert!(canonical_pipe_path(&"x".repeat(PIPE_NAME_CAPACITY)).is_err());
    }

    #[test]
    fn request_requires_one_input_and_preserves_a_scalar_id() {
        assert!(parse_command(&["request".into(), "--pipe".into(), "p".into(),]).is_err());
        assert!(parse_command(&[
            "request".into(),
            "--pipe".into(),
            "p".into(),
            "--stdin".into(),
            "--json".into(),
            "{}".into(),
        ])
        .is_err());
        let id = request_id(&json!({"id": 19, "command": "ping"})).unwrap();
        assert_eq!(id, json!(19));
        assert!(validate_response_id(&json!({"id": 20, "ok": true}), &id).is_err());
        assert!(validate_response_id(&json!({"id": 19, "ok": false}), &id).is_ok());
        assert!(request_id(&json!({"command": "ping"})).is_err());
    }
}
