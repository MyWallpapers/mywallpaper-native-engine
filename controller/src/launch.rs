//! An opt-in, owned launch stopped at the PE entrypoint. No global creation hook.
use std::mem::size_of;
use std::path::Path;
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

pub(crate) struct Prepared {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
    resumed: bool,
    debugging: bool,
}
impl Prepared {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn resumed(&self) -> bool {
        self.resumed
    }
    pub fn create(
        executable: &Path,
        arguments: &[String],
        directory: Option<&Path>,
    ) -> Result<Self, String> {
        let executable = executable.canonicalize().map_err(|e| e.to_string())?;
        let bytes = std::fs::read(&executable).map_err(|e| e.to_string())?;
        let image = crate::pe::Image::parse(&bytes)?;
        let entry_rva = image.entry_rva()? as usize;
        if entry_rva == 0 {
            return Err("launch image has no entrypoint".to_owned());
        }
        let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
        let file = wide(&executable.to_string_lossy());
        let directory = directory.map(|p| wide(&p.to_string_lossy()));
        let mut command = wide(
            &std::iter::once(executable.to_string_lossy().into_owned())
                .chain(arguments.iter().cloned())
                .map(|s| quote_argument(&s))
                .collect::<Vec<_>>()
                .join(" "),
        );
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessW(
                PCWSTR(file.as_ptr()),
                PWSTR(command.as_mut_ptr()),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(DEBUG_ONLY_THIS_PROCESS.0 | CREATE_NO_WINDOW.0),
                None,
                directory
                    .as_ref()
                    .map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
                &startup,
                &mut information,
            )
        }
        .map_err(|e| format!("controlled launch: {e}"))?;
        let mut prepared = Self {
            process: information.hProcess,
            thread: information.hThread,
            pid: information.dwProcessId,
            resumed: false,
            debugging: true,
        };
        unsafe { DebugSetProcessKillOnExit(false) }.map_err(|e| e.to_string())?;
        if crate::platform::identity(prepared.pid)?.architecture
            != crate::platform::native_architecture()
        {
            return Err("controlled launch image must match the companion architecture".to_owned());
        }
        let breakpoint: &[u8] = if cfg!(target_arch = "aarch64") {
            // Windows uses BRK #0xF000, as emitted by MSVC __debugbreak.
            // https://learn.microsoft.com/en-us/cpp/intrinsics/debugbreak
            &[0x00, 0x00, 0x3e, 0xd4]
        } else {
            &[0xcc]
        };
        let mut original = vec![0u8; breakpoint.len()];
        let mut entry = 0usize;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if Instant::now() >= deadline {
                return Err("entrypoint launch barrier timed out".to_owned());
            }
            let mut event = DEBUG_EVENT::default();
            if unsafe { WaitForDebugEvent(&mut event, 250) }.is_err() {
                continue;
            }
            let mut continuation = DBG_CONTINUE;
            let mut reached = false;
            unsafe {
                match event.dwDebugEventCode {
                    CREATE_PROCESS_DEBUG_EVENT => {
                        let info = event.u.CreateProcessInfo;
                        if !info.hFile.is_invalid() && info.hFile != HANDLE::default() {
                            let _ = CloseHandle(info.hFile);
                        }
                        entry = (info.lpBaseOfImage as usize)
                            .checked_add(entry_rva)
                            .ok_or("entrypoint address overflow")?;
                        let mut read = 0;
                        ReadProcessMemory(
                            prepared.process,
                            entry as *const _,
                            original.as_mut_ptr().cast(),
                            original.len(),
                            Some(&mut read),
                        )
                        .map_err(|e| e.to_string())?;
                        if read != original.len() {
                            return Err("short entrypoint read".to_owned());
                        }
                        write_code(prepared.process, entry, breakpoint)?;
                    }
                    LOAD_DLL_DEBUG_EVENT => {
                        let file = event.u.LoadDll.hFile;
                        if !file.is_invalid() && file != HANDLE::default() {
                            let _ = CloseHandle(file);
                        }
                    }
                    EXCEPTION_DEBUG_EVENT => {
                        let exception = event.u.Exception.ExceptionRecord;
                        if exception.ExceptionCode == EXCEPTION_BREAKPOINT {
                            if entry != 0
                                && exception.ExceptionAddress as usize == entry
                                && event.dwThreadId == information.dwThreadId
                            {
                                write_code(prepared.process, entry, &original)?;
                                #[repr(align(16))]
                                struct AlignedContext(CONTEXT);
                                let mut aligned_context = AlignedContext(CONTEXT::default());
                                let context = &mut aligned_context.0;
                                #[cfg(target_arch = "x86_64")]
                                {
                                    context.ContextFlags = CONTEXT_CONTROL_AMD64;
                                }
                                #[cfg(target_arch = "x86")]
                                {
                                    context.ContextFlags = CONTEXT_CONTROL_X86;
                                }
                                #[cfg(target_arch = "aarch64")]
                                {
                                    context.ContextFlags = CONTEXT_CONTROL_ARM64;
                                }
                                GetThreadContext(prepared.thread, context)
                                    .map_err(|e| format!("GetThreadContext at entrypoint: {e}"))?;
                                #[cfg(target_arch = "x86_64")]
                                {
                                    context.Rip = entry as u64;
                                }
                                #[cfg(target_arch = "x86")]
                                {
                                    context.Eip = entry as u32;
                                }
                                #[cfg(target_arch = "aarch64")]
                                {
                                    context.Pc = entry as u64;
                                }
                                SetThreadContext(prepared.thread, context)
                                    .map_err(|e| format!("SetThreadContext at entrypoint: {e}"))?;
                                if SuspendThread(prepared.thread) == u32::MAX {
                                    return Err("cannot hold entrypoint thread".to_owned());
                                }
                                reached = true;
                            }
                        } else {
                            continuation = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        let _ =
                            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                        return Err(format!(
                            "launched process exited before its entrypoint (0x{:08x})",
                            event.u.ExitProcess.dwExitCode
                        ));
                    }
                    _ => {}
                }
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)
                    .map_err(|e| e.to_string())?;
                if reached {
                    DebugActiveProcessStop(prepared.pid).map_err(|e| e.to_string())?;
                    prepared.debugging = false;
                    return Ok(prepared);
                }
            }
        }
    }
    pub fn resume(&mut self) -> Result<(), String> {
        if !self.resumed {
            if unsafe { ResumeThread(self.thread) } == u32::MAX {
                return Err("cannot resume application entrypoint".to_owned());
            }
            self.resumed = true;
        }
        Ok(())
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        unsafe {
            if !self.resumed {
                let _ = TerminateProcess(self.process, 2);
            }
            if self.debugging {
                let _ = DebugActiveProcessStop(self.pid);
            }
            let _ = CloseHandle(self.thread);
            let _ = CloseHandle(self.process);
        }
    }
}
unsafe fn write_code(process: HANDLE, address: usize, code: &[u8]) -> Result<(), String> {
    let mut previous = PAGE_PROTECTION_FLAGS::default();
    VirtualProtectEx(
        process,
        address as *const _,
        code.len(),
        PAGE_EXECUTE_READWRITE,
        &mut previous,
    )
    .map_err(|e| e.to_string())?;
    let mut written = 0;
    let result = WriteProcessMemory(
        process,
        address as *const _,
        code.as_ptr().cast(),
        code.len(),
        Some(&mut written),
    );
    let mut ignored = PAGE_PROTECTION_FLAGS::default();
    let restored = VirtualProtectEx(
        process,
        address as *const _,
        code.len(),
        previous,
        &mut ignored,
    );
    result.map_err(|e| e.to_string())?;
    restored.map_err(|e| e.to_string())?;
    if written != code.len() {
        return Err("short entrypoint patch write".to_owned());
    }
    FlushInstructionCache(process, Some(address as *const _), code.len()).map_err(|e| e.to_string())
}
fn quote_argument(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
        } else {
            out.push_str(&"\\".repeat(slashes));
        }
        slashes = 0;
        out.push(c);
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}
#[cfg(test)]
mod tests {
    use super::quote_argument;
    #[test]
    fn quotes_empty_embedded_quotes_and_trailing_slashes() {
        assert_eq!(quote_argument(""), "\"\"");
        assert_eq!(quote_argument("a b"), "\"a b\"");
        assert_eq!(quote_argument("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_argument("C:\\dir\\"), "\"C:\\dir\\\\\"");
    }
}
