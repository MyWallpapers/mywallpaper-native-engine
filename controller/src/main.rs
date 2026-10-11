use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;
use std::time::Duration;

mod process_v2;

const PIPE_IO_TIMEOUT: Duration = Duration::from_secs(10);
const PIPE_NAME_CAPACITY: usize = 192;
const PIPE_PREFIX: &str = r"\\.\pipe\";

#[cfg(all(windows, not(target_pointer_width = "64")))]
compile_error!("mw-native-controller must be built as x64");

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Identity {
        pid: u32,
    },
    Inject {
        pid: u32,
        creation_time: u64,
        agent: PathBuf,
        pipe: String,
    },
    Request {
        pipe: String,
        json: Option<String>,
        file: Option<PathBuf>,
        stdin: bool,
    },
}

fn usage() -> &'static str {
    "Usage:\n  mw-native-controller identity --pid PID\n  mw-native-controller inject --pid PID --creation-time FILETIME --agent DLL --pipe NAME\n  mw-native-controller request --pipe NAME (--json JSON | --file PATH | --stdin)"
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
            reject_unknown(&options, &["--pid", "--creation-time", "--agent", "--pipe"])?;
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
        Command::Identity { pid } => {
            let identity = platform::identity(pid)?;
            serde_json::to_string(&identity).map_err(|error| error.to_string())
        }
        Command::Inject {
            pid,
            creation_time,
            agent,
            pipe,
        } => {
            let result = platform::inject(pid, creation_time, &agent, &pipe)?;
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
    if args.is_empty() {
        if let Err(error) = process_v2::run() {
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
pub(crate) mod platform {
    use super::{canonical_pipe_path, PIPE_IO_TIMEOUT, PIPE_NAME_CAPACITY};
    use serde::Serialize;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::Read;
    use std::mem::{size_of, transmute};
    use std::path::Path;
    use std::time::{Duration, Instant};
    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, DuplicateHandle, FreeLibrary, GetLastError, DUPLICATE_CLOSE_SOURCE,
        DUPLICATE_HANDLE_OPTIONS, DUPLICATE_SAME_ACCESS, ERROR_BAD_LENGTH, ERROR_FILE_NOT_FOUND,
        ERROR_IO_PENDING, ERROR_NO_MORE_FILES, ERROR_PIPE_BUSY, FILETIME, GENERIC_READ,
        GENERIC_WRITE, HANDLE, HMODULE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_OVERLAPPED,
        FILE_SHARE_MODE, OPEN_EXISTING, SYNCHRONIZE,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
        CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW,
        DONT_RESOLVE_DLL_REFERENCES, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
        IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, CreateRemoteThread, GetCurrentProcess, GetCurrentProcessId,
        GetExitCodeThread, GetProcessTimes, IsWow64Process2, OpenProcess, WaitForSingleObject,
        LPTHREAD_START_ROUTINE, PROCESS_ACCESS_RIGHTS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
        PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, GetWindowThreadProcessId};

    const REMOTE_THREAD_TIMEOUT: Duration = Duration::from_secs(10);
    const MODULE_ENUM_FLAGS: CREATE_TOOLHELP_SNAPSHOT_FLAGS =
        CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPMODULE.0 | TH32CS_SNAPMODULE32.0);

    #[derive(Serialize)]
    pub struct Identity {
        pid: u32,
        #[serde(rename = "creationTime")]
        creation_time: u64,
        architecture: String,
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn new(handle: HANDLE) -> Self {
            Self(handle)
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if self.0 != HANDLE::default() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalLibrary(HMODULE);

    impl Drop for LocalLibrary {
        fn drop(&mut self) {
            if self.0 != HMODULE::default() {
                unsafe {
                    let _ = FreeLibrary(self.0);
                }
            }
        }
    }

    struct RemoteAllocation {
        process: HANDLE,
        address: *mut c_void,
        safe_to_free: bool,
    }

    struct RemoteOwnerHandle {
        target_process: HANDLE,
        remote: HANDLE,
        armed: bool,
    }

    impl RemoteOwnerHandle {
        fn transfer_to_agent(&mut self) {
            self.armed = false;
        }
    }

    impl Drop for RemoteOwnerHandle {
        fn drop(&mut self) {
            if !self.armed || self.remote == HANDLE::default() {
                return;
            }
            let mut temporary = HANDLE::default();
            let options =
                DUPLICATE_HANDLE_OPTIONS(DUPLICATE_SAME_ACCESS.0 | DUPLICATE_CLOSE_SOURCE.0);
            if unsafe {
                DuplicateHandle(
                    self.target_process,
                    self.remote,
                    GetCurrentProcess(),
                    &mut temporary,
                    0,
                    false,
                    options,
                )
            }
            .is_ok()
                && temporary != HANDLE::default()
            {
                unsafe {
                    let _ = CloseHandle(temporary);
                }
            }
        }
    }

    impl RemoteAllocation {
        fn allocate(process: HANDLE, size: usize) -> Result<Self, String> {
            let address = unsafe {
                VirtualAllocEx(
                    process,
                    None,
                    size,
                    VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0 | MEM_RESERVE.0),
                    PAGE_READWRITE,
                )
            };
            if address.is_null() {
                return Err(last_error("VirtualAllocEx"));
            }
            Ok(Self {
                process,
                address,
                safe_to_free: true,
            })
        }

        fn write(&self, bytes: &[u8]) -> Result<(), String> {
            let mut written = 0usize;
            unsafe {
                windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                    self.process,
                    self.address,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    Some(&mut written),
                )
            }
            .map_err(|error| format!("WriteProcessMemory failed: {error}"))?;
            if written != bytes.len() {
                return Err(format!(
                    "WriteProcessMemory copied {written} of {} bytes",
                    bytes.len()
                ));
            }
            Ok(())
        }

        fn pointer(&self) -> *mut c_void {
            self.address
        }

        fn retain_until_thread_finishes(&mut self) {
            self.safe_to_free = false;
        }

        fn thread_finished(&mut self) {
            self.safe_to_free = true;
        }
    }

    impl Drop for RemoteAllocation {
        fn drop(&mut self) {
            if self.safe_to_free && !self.address.is_null() {
                unsafe {
                    let _ = VirtualFreeEx(
                        self.process,
                        self.address,
                        0,
                        VIRTUAL_FREE_TYPE(MEM_RELEASE.0),
                    );
                }
            }
        }
    }

    #[derive(Clone)]
    struct RemoteModule {
        name: String,
        path: String,
        base: usize,
        size: usize,
    }

    fn last_error(operation: &str) -> String {
        let code = unsafe { GetLastError().0 };
        format!("{operation} failed with Windows error {code}")
    }

    fn open_process(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Result<OwnedHandle, String> {
        let handle = unsafe { OpenProcess(rights, false, pid) }
            .map_err(|error| format!("OpenProcess({pid}) failed: {error}"))?;
        Ok(OwnedHandle::new(handle))
    }

    fn identity_for_handle(handle: HANDLE, pid: u32) -> Result<Identity, String> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }
            .map_err(|error| format!("GetProcessTimes({pid}) failed: {error}"))?;

        let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        unsafe { IsWow64Process2(handle, &mut process_machine, Some(&mut native_machine)) }
            .map_err(|error| format!("IsWow64Process2({pid}) failed: {error}"))?;
        let machine = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
            native_machine
        } else {
            process_machine
        };

        Ok(Identity {
            pid,
            creation_time: ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64,
            architecture: architecture_name(machine),
        })
    }

    fn architecture_name(machine: IMAGE_FILE_MACHINE) -> String {
        if machine == IMAGE_FILE_MACHINE_AMD64 {
            "x64".to_owned()
        } else if machine == IMAGE_FILE_MACHINE_I386 {
            "x86".to_owned()
        } else if machine == IMAGE_FILE_MACHINE_ARM64 {
            "arm64".to_owned()
        } else {
            format!("unknown-0x{:04x}", machine.0)
        }
    }

    pub fn identity(pid: u32) -> Result<Identity, String> {
        let process = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        identity_for_handle(process.raw(), pid)
    }

    pub fn current_process_identity() -> Result<(u32, u64), String> {
        let pid = unsafe { GetCurrentProcessId() };
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        }
        .map_err(|error| format!("GetProcessTimes(current process) failed: {error}"))?;
        Ok((
            pid,
            ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64,
        ))
    }

    pub fn find_target_process(
        image_name: &str,
        window_class: Option<&str>,
    ) -> Result<(u32, u64), String> {
        let pid = if let Some(class_name) = window_class {
            let class_wide = class_name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let window = unsafe { FindWindowW(PCWSTR(class_wide.as_ptr()), PCWSTR::null()) }
                .map_err(|error| format!("FindWindowW({class_name}) failed: {error}"))?;
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
            if pid == 0 {
                return Err(format!("window class {class_name} has no owner process"));
            }
            if owner_name_for_pid(pid)?.map_or(true, |name| !name.eq_ignore_ascii_case(image_name))
            {
                return Err(format!(
                    "window class {class_name} is not owned by {image_name}"
                ));
            }
            pid
        } else {
            let candidates = processes_named(image_name)?;
            match candidates.as_slice() {
                [pid] => *pid,
                [] => return Err(format!("target process {image_name} is not running")),
                _ => return Err(format!(
                    "target process name {image_name} is ambiguous; descriptor must include windowClass"
                )),
            }
        };
        let identity = identity(pid)?;
        if identity.architecture != "x64" {
            return Err(format!("target {image_name} is not x64"));
        }
        Ok((identity.pid, identity.creation_time))
    }

    fn processes_named(image_name: &str) -> Result<Vec<u32>, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|error| format!("CreateToolhelp32Snapshot(processes) failed: {error}"))?;
        let snapshot = OwnedHandle::new(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        unsafe { Process32FirstW(snapshot.raw(), &mut entry) }
            .map_err(|error| format!("Process32FirstW failed: {error}"))?;
        let mut result = Vec::new();
        loop {
            if wide_string(&entry.szExeFile).eq_ignore_ascii_case(image_name) {
                result.push(entry.th32ProcessID);
            }
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            if let Err(error) = unsafe { Process32NextW(snapshot.raw(), &mut entry) } {
                let code = unsafe { GetLastError().0 };
                if code == ERROR_NO_MORE_FILES.0 {
                    break;
                }
                return Err(format!("Process32NextW failed: {error}"));
            }
        }
        Ok(result)
    }

    fn owner_name_for_pid(pid: u32) -> Result<Option<String>, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|error| format!("CreateToolhelp32Snapshot(processes) failed: {error}"))?;
        let snapshot = OwnedHandle::new(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        unsafe { Process32FirstW(snapshot.raw(), &mut entry) }
            .map_err(|error| format!("Process32FirstW failed: {error}"))?;
        loop {
            if entry.th32ProcessID == pid {
                return Ok(Some(wide_string(&entry.szExeFile)));
            }
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            if let Err(error) = unsafe { Process32NextW(snapshot.raw(), &mut entry) } {
                let code = unsafe { GetLastError().0 };
                if code == ERROR_NO_MORE_FILES.0 {
                    return Ok(None);
                }
                return Err(format!("Process32NextW failed: {error}"));
            }
        }
    }

    fn expected_identity(
        process: HANDLE,
        pid: u32,
        expected_creation_time: u64,
    ) -> Result<Identity, String> {
        let identity = identity_for_handle(process, pid)?;
        if identity.creation_time != expected_creation_time {
            return Err(format!(
                "target PID {pid} was reused: expected creation time {expected_creation_time}, got {}",
                identity.creation_time
            ));
        }
        if identity.architecture != "x64" {
            return Err(format!(
                "target PID {pid} is {}, but this prototype only injects x64 processes",
                identity.architecture
            ));
        }
        Ok(identity)
    }

    fn module_path(module: HMODULE) -> Result<String, String> {
        let mut buffer = vec![0u16; 32768];
        let length = unsafe { GetModuleFileNameW(module, &mut buffer) } as usize;
        if length == 0 {
            return Err(last_error("GetModuleFileNameW"));
        }
        if length >= buffer.len() {
            return Err("module path exceeds the Windows path buffer".to_owned());
        }
        Ok(String::from_utf16_lossy(&buffer[..length]))
    }

    fn module_basename(path: &str) -> Result<String, String> {
        Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or_else(|| format!("cannot determine module basename from {path:?}"))
    }

    fn normalize_windows_path(path: &str) -> String {
        let mut path = path.replace('/', "\\");
        if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
            path = format!(r"\\{rest}");
        } else if let Some(rest) = path.strip_prefix(r"\\?\") {
            path = rest.to_owned();
        }
        path.to_lowercase()
    }

    fn remote_modules(pid: u32) -> Result<Vec<RemoteModule>, String> {
        let snapshot = {
            let mut result = None;
            for attempt in 0..4 {
                match unsafe { CreateToolhelp32Snapshot(MODULE_ENUM_FLAGS, pid) } {
                    Ok(snapshot) => {
                        result = Some(snapshot);
                        break;
                    }
                    Err(error) => {
                        let code = unsafe { GetLastError().0 };
                        if code != ERROR_BAD_LENGTH.0 || attempt == 3 {
                            return Err(format!("CreateToolhelp32Snapshot({pid}) failed: {error}"));
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            result.ok_or_else(|| format!("CreateToolhelp32Snapshot({pid}) failed"))?
        };
        let snapshot = OwnedHandle::new(snapshot);
        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        unsafe { Module32FirstW(snapshot.raw(), &mut entry) }
            .map_err(|error| format!("Module32FirstW({pid}) failed: {error}"))?;

        let mut modules = Vec::new();
        loop {
            modules.push(RemoteModule {
                name: wide_string(&entry.szModule),
                path: wide_string(&entry.szExePath),
                base: entry.modBaseAddr as usize,
                size: entry.modBaseSize as usize,
            });
            entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
            if let Err(error) = unsafe { Module32NextW(snapshot.raw(), &mut entry) } {
                let code = unsafe { GetLastError().0 };
                if code == ERROR_NO_MORE_FILES.0 {
                    break;
                }
                return Err(format!("Module32NextW({pid}) failed: {error}"));
            }
        }
        Ok(modules)
    }

    fn wide_string(value: &[u16]) -> String {
        let end = value
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(value.len());
        String::from_utf16_lossy(&value[..end])
    }

    fn find_remote_module_by_path(pid: u32, path: &str) -> Result<Option<RemoteModule>, String> {
        let expected = normalize_windows_path(path);
        let basename = module_basename(path)?;
        for module in remote_modules(pid)? {
            if module.name.eq_ignore_ascii_case(&basename) {
                if normalize_windows_path(&module.path) == expected {
                    return Ok(Some(module));
                }
                return Err(format!(
                    "target already has a different module named {}; refusing to use it",
                    module.name
                ));
            }
        }
        Ok(None)
    }

    fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
        let mut file =
            File::open(path).map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|error| {
                format!("cannot read {} while hashing: {error}", path.display())
            })?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(hasher.finalize().into())
    }

    fn find_remote_agent_by_digest(
        pid: u32,
        agent_path: &Path,
        expected_digest: &[u8; 32],
    ) -> Result<Option<RemoteModule>, String> {
        let basename = agent_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "cannot determine native agent DLL file name".to_owned())?;
        let mut match_found: Option<RemoteModule> = None;
        for module in remote_modules(pid)? {
            if !module.name.eq_ignore_ascii_case(basename) {
                continue;
            }
            let remote_digest = sha256_file(Path::new(&module.path))?;
            if &remote_digest != expected_digest {
                return Err(format!(
                    "target already has a different {basename} binary loaded; only byte-identical engine builds can share one agent runtime"
                ));
            }
            if match_found.is_some() {
                return Err(format!(
                    "target has more than one byte-identical {basename} image loaded; refusing ambiguous agent ownership"
                ));
            }
            match_found = Some(module);
        }
        Ok(match_found)
    }

    fn resolve_remote_function(
        pid: u32,
        function_address: usize,
        expected_local_module: Option<HMODULE>,
    ) -> Result<usize, String> {
        if function_address == 0 {
            return Err("cannot resolve a null local function address".to_owned());
        }
        let mut owner = HMODULE::default();
        unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                PCWSTR(function_address as *const u16),
                &mut owner,
            )
        }
        .map_err(|error| format!("GetModuleHandleExW(address) failed: {error}"))?;
        if let Some(expected) = expected_local_module {
            if owner != expected {
                return Err("MwAgentStart is not owned by the agent DLL".to_owned());
            }
        }

        let local_base = owner.0 as usize;
        let rva = function_address
            .checked_sub(local_base)
            .ok_or_else(|| "resolved function precedes its owning module".to_owned())?;
        let owner_path = module_path(owner)?;
        let remote_module = find_remote_module_by_path(pid, &owner_path)?
            .ok_or_else(|| format!("target has not loaded the function owner {owner_path}"))?;
        if rva >= remote_module.size {
            return Err("resolved function RVA falls outside the target module".to_owned());
        }
        remote_module
            .base
            .checked_add(rva)
            .ok_or_else(|| "remote function address overflow".to_owned())
    }

    fn resolve_agent_function(
        function_address: usize,
        expected_local_agent: HMODULE,
        remote_agent: &RemoteModule,
    ) -> Result<usize, String> {
        if function_address == 0 {
            return Err("cannot resolve a null local agent function address".to_owned());
        }
        let mut owner = HMODULE::default();
        unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                PCWSTR(function_address as *const u16),
                &mut owner,
            )
        }
        .map_err(|error| format!("GetModuleHandleExW(agent address) failed: {error}"))?;
        if owner != expected_local_agent {
            return Err("MwAgentStart is not owned by the local agent DLL".to_owned());
        }
        let local_base = owner.0 as usize;
        let rva = function_address
            .checked_sub(local_base)
            .ok_or_else(|| "MwAgentStart precedes its owning module".to_owned())?;
        if rva >= remote_agent.size {
            return Err(
                "MwAgentStart RVA falls outside the loaded byte-identical agent image".to_owned(),
            );
        }
        remote_agent
            .base
            .checked_add(rva)
            .ok_or_else(|| "remote MwAgentStart address overflow".to_owned())
    }

    fn get_load_library_address(pid: u32) -> Result<usize, String> {
        let kernel32_name = "kernel32.dll"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let kernel32 = unsafe { GetModuleHandleW(PCWSTR(kernel32_name.as_ptr())) }
            .map_err(|error| format!("GetModuleHandleW(kernel32.dll) failed: {error}"))?;
        let proc = unsafe { GetProcAddress(kernel32, PCSTR(c"LoadLibraryW".as_ptr().cast())) }
            .ok_or_else(|| "GetProcAddress(LoadLibraryW) failed".to_owned())?;
        let local_address = proc as *const () as usize;
        resolve_remote_function(pid, local_address, None)
    }

    fn remote_thread_start(address: usize) -> LPTHREAD_START_ROUTINE {
        let function =
            unsafe { transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(address) };
        Some(function)
    }

    fn start_remote_thread(
        process: HANDLE,
        start_address: usize,
        parameter: *mut c_void,
        mut keep_alive: Option<&mut RemoteAllocation>,
        mut on_created: Option<&mut dyn FnMut()>,
        timeout: Duration,
    ) -> Result<u32, String> {
        if let Some(allocation) = keep_alive.as_deref_mut() {
            allocation.retain_until_thread_finishes();
        }
        let thread = match unsafe {
            CreateRemoteThread(
                process,
                None,
                0,
                remote_thread_start(start_address),
                Some(parameter.cast_const()),
                0,
                None,
            )
        } {
            Ok(thread) => OwnedHandle::new(thread),
            Err(error) => {
                if let Some(allocation) = keep_alive {
                    allocation.thread_finished();
                }
                return Err(format!("CreateRemoteThread failed: {error}"));
            }
        };

        // Notify the caller only after Windows has created the remote thread.
        // Before this point, a duplicated owner handle is still ours to close;
        // after this point, MwAgentStart is responsible for validating and
        // closing it on every exit path, including a late completion.
        if let Some(callback) = on_created.as_deref_mut() {
            callback();
        }

        let wait = unsafe { WaitForSingleObject(thread.raw(), timeout.as_millis() as u32) };
        if wait == WAIT_TIMEOUT {
            return Err(format!(
                "remote thread timed out after {} seconds; its remote buffer was retained because the thread may still be using it",
                timeout.as_secs()
            ));
        }
        if wait != WAIT_OBJECT_0 {
            return Err(last_error("WaitForSingleObject(remote thread)"));
        }
        if let Some(allocation) = keep_alive {
            allocation.thread_finished();
        }
        let mut exit_code = 0u32;
        unsafe { GetExitCodeThread(thread.raw(), &mut exit_code) }
            .map_err(|error| format!("GetExitCodeThread failed: {error}"))?;
        Ok(exit_code)
    }

    pub fn inject(
        pid: u32,
        creation_time: u64,
        agent_path: &Path,
        pipe_name: &str,
    ) -> Result<Value, String> {
        let pipe_name = canonical_pipe_path(pipe_name)?;
        let agent_path = std::fs::canonicalize(agent_path)
            .map_err(|error| format!("cannot resolve agent path: {error}"))?;
        if !agent_path.is_file() {
            return Err(format!(
                "agent path is not a file: {}",
                agent_path.display()
            ));
        }
        let agent_path_string = agent_path
            .to_str()
            .ok_or_else(|| "agent path is not valid Unicode".to_owned())?;
        let agent_path_wide = agent_path_string
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let expected_path = agent_path_string;
        let agent_digest = sha256_file(&agent_path)?;

        let rights = PROCESS_ACCESS_RIGHTS(
            PROCESS_CREATE_THREAD.0
                | PROCESS_QUERY_INFORMATION.0
                | PROCESS_DUP_HANDLE.0
                | PROCESS_VM_OPERATION.0
                | PROCESS_VM_READ.0
                | PROCESS_VM_WRITE.0,
        );
        let process = open_process(pid, rights)?;
        let identity = expected_identity(process.raw(), pid, creation_time)?;
        let remote_agent = match find_remote_agent_by_digest(pid, &agent_path, &agent_digest)? {
            Some(agent) => agent,
            None => {
                let load_library_address = get_load_library_address(pid)?;
                let path_bytes = unsafe {
                    std::slice::from_raw_parts(
                        agent_path_wide.as_ptr().cast::<u8>(),
                        agent_path_wide.len() * size_of::<u16>(),
                    )
                };
                let mut remote_path = RemoteAllocation::allocate(process.raw(), path_bytes.len())?;
                remote_path.write(path_bytes)?;
                let _load_exit = start_remote_thread(
                    process.raw(),
                    load_library_address,
                    remote_path.pointer(),
                    Some(&mut remote_path),
                    None,
                    REMOTE_THREAD_TIMEOUT,
                )?;
                let _ = expected_identity(process.raw(), pid, creation_time)?;
                find_remote_module_by_path(pid, expected_path)?.ok_or_else(|| {
                    "LoadLibraryW completed but the agent DLL is not in the target".to_owned()
                })?
            }
        };

        let local_agent = unsafe {
            LoadLibraryExW(
                PCWSTR(agent_path_wide.as_ptr()),
                HANDLE::default(),
                DONT_RESOLVE_DLL_REFERENCES,
            )
        }
        .map_err(|error| format!("LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) failed: {error}"))?;
        let local_agent = LocalLibrary(local_agent);
        let entry =
            unsafe { GetProcAddress(local_agent.0, PCSTR(c"MwAgentStart".as_ptr().cast())) }
                .ok_or_else(|| "agent DLL does not export MwAgentStart".to_owned())?;
        let entry_address = entry as *const () as usize;
        if sha256_file(&agent_path)? != agent_digest {
            return Err("agent DLL changed on disk while preparing injection".to_owned());
        }
        let remote_entry = resolve_agent_function(entry_address, local_agent.0, &remote_agent)?;
        let confirmed_remote_agent = find_remote_agent_by_digest(pid, &agent_path, &agent_digest)?
            .ok_or_else(|| "agent DLL disappeared during bootstrap".to_owned())?;
        if remote_agent.base != confirmed_remote_agent.base {
            return Err("agent module base changed during bootstrap".to_owned());
        }

        let owner_pid = unsafe { GetCurrentProcessId() };
        let mut owner_creation = FILETIME::default();
        let mut owner_exit = FILETIME::default();
        let mut owner_kernel = FILETIME::default();
        let mut owner_user = FILETIME::default();
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut owner_creation,
                &mut owner_exit,
                &mut owner_kernel,
                &mut owner_user,
            )
        }
        .map_err(|error| format!("GetProcessTimes(companion) failed: {error}"))?;
        let owner_creation_time =
            ((owner_creation.dwHighDateTime as u64) << 32) | owner_creation.dwLowDateTime as u64;
        let mut remote_owner_process = HANDLE::default();
        let owner_access = PROCESS_QUERY_LIMITED_INFORMATION.0 | SYNCHRONIZE.0;
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentProcess(),
                process.raw(),
                &mut remote_owner_process,
                owner_access,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|error| format!("DuplicateHandle(companion owner) failed: {error}"))?;
        let mut remote_owner = RemoteOwnerHandle {
            target_process: process.raw(),
            remote: remote_owner_process,
            armed: true,
        };
        let mut config = AgentStartConfig::new(
            pid,
            creation_time,
            owner_pid,
            owner_creation_time,
            remote_owner_process.0 as usize as u64,
            &pipe_name,
        )?;
        let config_bytes = unsafe {
            std::slice::from_raw_parts(
                (&mut config as *mut AgentStartConfig).cast::<u8>(),
                size_of::<AgentStartConfig>(),
            )
        };
        let mut remote_config = RemoteAllocation::allocate(process.raw(), config_bytes.len())?;
        remote_config.write(config_bytes)?;
        let mut transfer_owner = || remote_owner.transfer_to_agent();
        let start_status = start_remote_thread(
            process.raw(),
            remote_entry,
            remote_config.pointer(),
            Some(&mut remote_config),
            Some(&mut transfer_owner),
            REMOTE_THREAD_TIMEOUT,
        )?;
        if start_status != 0 {
            return Err(format!("MwAgentStart returned status {start_status}"));
        }
        let _ = expected_identity(process.raw(), pid, creation_time)?;

        Ok(json!({
            "ok": true,
            "code": "OK",
            "status": "started",
            "pid": identity.pid,
            "creationTime": identity.creation_time,
            "architecture": identity.architecture,
            "pipe": pipe_name,
        }))
    }

    #[repr(C)]
    struct AgentStartConfig {
        struct_size: u32,
        target_pid: u32,
        target_creation_time: u64,
        owner_pid: u32,
        reserved: u32,
        owner_creation_time: u64,
        owner_process_handle: u64,
        pipe_name: [u16; PIPE_NAME_CAPACITY],
    }

    impl AgentStartConfig {
        fn new(
            pid: u32,
            creation_time: u64,
            owner_pid: u32,
            owner_creation_time: u64,
            owner_process_handle: u64,
            pipe: &str,
        ) -> Result<Self, String> {
            let encoded = pipe.encode_utf16().collect::<Vec<_>>();
            if encoded.len() >= PIPE_NAME_CAPACITY {
                return Err("pipe name does not fit in MwAgentStartConfig".to_owned());
            }
            let mut pipe_name = [0u16; PIPE_NAME_CAPACITY];
            pipe_name[..encoded.len()].copy_from_slice(&encoded);
            Ok(Self {
                struct_size: size_of::<Self>() as u32,
                target_pid: pid,
                target_creation_time: creation_time,
                owner_pid,
                reserved: 0,
                owner_creation_time,
                owner_process_handle,
                pipe_name,
            })
        }
    }

    pub fn request(pipe_name: &str, request: &Value) -> Result<Value, String> {
        AgentPipeSession::connect(pipe_name)?.request(request)
    }

    pub struct AgentPipeSession {
        pipe: OwnedHandle,
    }

    impl AgentPipeSession {
        pub fn connect(pipe_name: &str) -> Result<Self, String> {
            let pipe_name = canonical_pipe_path(pipe_name)?;
            let path_wide = pipe_name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let deadline = Instant::now() + PIPE_IO_TIMEOUT;
            Ok(Self {
                pipe: open_pipe(&path_wide, deadline)?,
            })
        }

        pub fn request(&mut self, request: &Value) -> Result<Value, String> {
            let request_bytes = serde_json::to_vec(request)
                .map_err(|error| format!("cannot encode request JSON: {error}"))?;
            let mut framed_request = request_bytes;
            framed_request.push(b'\n');
            let deadline = Instant::now() + PIPE_IO_TIMEOUT;
            write_all_overlapped(self.pipe.raw(), &framed_request, deadline)?;
            let response_bytes = read_line(self.pipe.raw(), deadline)?;
            serde_json::from_slice(&response_bytes)
                .map_err(|error| format!("pipe returned invalid JSON: {error}"))
        }
    }

    fn open_pipe(path: &[u16], deadline: Instant) -> Result<OwnedHandle, String> {
        loop {
            let remaining = remaining_timeout(deadline)?;
            let ready = unsafe { WaitNamedPipeW(PCWSTR(path.as_ptr()), remaining) };
            if !ready.as_bool() {
                let code = unsafe { GetLastError().0 };
                if (code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PIPE_BUSY.0)
                    && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                return Err(format!("WaitNamedPipeW failed with Windows error {code}"));
            }
            match unsafe {
                CreateFileW(
                    PCWSTR(path.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_OVERLAPPED.0),
                    HANDLE::default(),
                )
            } {
                Ok(handle) => return Ok(OwnedHandle::new(handle)),
                Err(error) => {
                    let code = unsafe { GetLastError().0 };
                    if (code == ERROR_PIPE_BUSY.0 || code == ERROR_FILE_NOT_FOUND.0)
                        && Instant::now() < deadline
                    {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    return Err(format!("CreateFileW(named pipe) failed: {error}"));
                }
            }
        }
    }

    fn remaining_timeout(deadline: Instant) -> Result<u32, String> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("named pipe operation timed out".to_owned());
        }
        Ok(remaining.as_millis().clamp(1, u32::MAX as u128) as u32)
    }

    enum IoBuffer<'a> {
        Write(&'a [u8]),
        Read(&'a mut [u8]),
    }

    fn overlapped_io(
        handle: HANDLE,
        mut buffer: IoBuffer<'_>,
        deadline: Instant,
    ) -> Result<usize, String> {
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|error| format!("CreateEventW failed: {error}"))?;
        let event = OwnedHandle::new(event);
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        let mut transferred = 0u32;
        let is_write = matches!(&buffer, IoBuffer::Write(_));
        let result = unsafe {
            match &mut buffer {
                IoBuffer::Write(bytes) => WriteFile(
                    handle,
                    Some(*bytes),
                    Some(&mut transferred),
                    Some(&mut overlapped),
                ),
                IoBuffer::Read(bytes) => ReadFile(
                    handle,
                    Some(&mut **bytes),
                    Some(&mut transferred),
                    Some(&mut overlapped),
                ),
            }
        };
        if result.is_ok() {
            return Ok(transferred as usize);
        }
        let error = result.unwrap_err();
        let last = unsafe { GetLastError().0 };
        if last != ERROR_IO_PENDING.0 {
            return Err(format!(
                "{} named pipe failed: {error}",
                if is_write { "write to" } else { "read from" }
            ));
        }

        let wait = match remaining_timeout(deadline) {
            Ok(remaining) => unsafe { WaitForSingleObject(event.raw(), remaining) },
            Err(_) => WAIT_TIMEOUT,
        };
        if wait == WAIT_TIMEOUT {
            unsafe {
                let _ = CancelIoEx(handle, Some(&overlapped));
                let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
            }
            return Err("named pipe operation timed out".to_owned());
        }
        if wait != WAIT_OBJECT_0 {
            let code = unsafe { GetLastError().0 };
            unsafe {
                let _ = CancelIoEx(handle, Some(&overlapped));
                let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
            }
            return Err(format!(
                "WaitForSingleObject(named pipe event) failed with Windows error {code}"
            ));
        }
        unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, false) }
            .map_err(|error| format!("GetOverlappedResult(named pipe) failed: {error}"))?;
        Ok(transferred as usize)
    }

    fn write_all_overlapped(
        handle: HANDLE,
        mut bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), String> {
        while !bytes.is_empty() {
            let transferred = overlapped_io(handle, IoBuffer::Write(bytes), deadline)?;
            if transferred == 0 {
                return Err("named pipe closed during request write".to_owned());
            }
            bytes = &bytes[transferred..];
        }
        Ok(())
    }

    fn read_line(handle: HANDLE, deadline: Instant) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let count = overlapped_io(handle, IoBuffer::Read(&mut chunk), deadline)?;
            if count == 0 {
                return Err("named pipe closed before sending a newline response".to_owned());
            }
            let chunk = &chunk[..count];
            if let Some(newline) = chunk.iter().position(|byte| *byte == b'\n') {
                if chunk[newline + 1..]
                    .iter()
                    .any(|byte| !byte.is_ascii_whitespace())
                {
                    return Err("named pipe sent more than one response".to_owned());
                }
                output.try_reserve(newline).map_err(|error| {
                    format!("cannot allocate internal pipe response buffer: {error}")
                })?;
                output.extend_from_slice(&chunk[..newline]);
                if output.last() == Some(&b'\r') {
                    output.pop();
                }
                return Ok(output);
            }
            output.try_reserve(count).map_err(|error| {
                format!("cannot allocate internal pipe response buffer: {error}")
            })?;
            output.extend_from_slice(chunk);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bootstrap_matches_the_c_header_layout() {
            assert_eq!(size_of::<AgentStartConfig>(), 424);
            let config =
                AgentStartConfig::new(42, 1234, 9, 5678, 0x1234, r"\\.\pipe\mw-test").unwrap();
            assert_eq!(config.struct_size, 424);
            assert_eq!(config.target_pid, 42);
            assert_eq!(config.target_creation_time, 1234);
            assert_eq!(config.owner_pid, 9);
            assert_eq!(config.owner_creation_time, 5678);
            assert_eq!(config.owner_process_handle, 0x1234);
            assert_eq!(wide_string(&config.pipe_name), r"\\.\pipe\mw-test");
        }
    }
}

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
        Err("this controller only runs on Windows".to_owned())
    }

    pub fn inject(
        _pid: u32,
        _creation_time: u64,
        _agent: &Path,
        _pipe: &str,
    ) -> Result<Value, String> {
        Err("this controller only injects on Windows".to_owned())
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
