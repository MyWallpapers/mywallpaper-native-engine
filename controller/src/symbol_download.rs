//! Minimal Microsoft public symbol-server transport using Windows' HTTP client.
//! DbgHelp validates GUID/age and module identity after download. No target IPC waits.
use std::io::Write;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Networking::WinHttp::*;
pub(crate) fn fetch(file: &str, key: &str, directory: &Path) -> Result<(), String> {
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
    struct Http(*mut std::ffi::c_void);
    impl Http {
        fn checked(handle: *mut std::ffi::c_void) -> Result<Self, String> {
            if handle.is_null() {
                Err(format!("symbol HTTP error {}", unsafe { GetLastError().0 }))
            } else {
                Ok(Self(handle))
            }
        }
    }
    impl Drop for Http {
        fn drop(&mut self) {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
    std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let temporary = directory.join(format!("{file}.{}.tmp", std::process::id()));
    let destination = directory.join(file);
    let result = (|| unsafe {
        let agent = wide("MyWallpaperNativeEngine/0.2");
        let server = wide("msdl.microsoft.com");
        let object = wide(&format!("/download/symbols/{file}/{key}/{file}"));
        let verb = wide("GET");
        let session = Http::checked(WinHttpOpen(
            PCWSTR(agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ))?;
        WinHttpSetTimeouts(session.0, 5000, 5000, 15000, 15000).map_err(|e| e.to_string())?;
        let connection = Http::checked(WinHttpConnect(session.0, PCWSTR(server.as_ptr()), 443, 0))?;
        let request = Http::checked(WinHttpOpenRequest(
            connection.0,
            PCWSTR(verb.as_ptr()),
            PCWSTR(object.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ))?;
        WinHttpSendRequest(request.0, None, None, 0, 0, 0)
            .map_err(|e| format!("symbol download: {e}"))?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut()).map_err(|e| e.to_string())?;
        let mut status = 0u32;
        let mut length = 4u32;
        let mut index = 0u32;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some((&mut status as *mut u32).cast()),
            &mut length,
            &mut index,
        )
        .map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!("Microsoft symbol server returned HTTP {status} for {file}/{key}; provide a local PDB/searchPath when unavailable"));
        }
        let mut output = std::fs::File::create(&temporary).map_err(|e| e.to_string())?;
        let mut buffer = [0u8; 65536];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if std::time::Instant::now() >= deadline {
                return Err("symbol download exceeded 120 seconds".to_owned());
            }
            let mut count = 0;
            WinHttpReadData(
                request.0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut count,
            )
            .map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            output
                .write_all(&buffer[..count as usize])
                .map_err(|e| e.to_string())?;
        }
        output.sync_all().map_err(|e| e.to_string())?;
        drop(output);
        match std::fs::rename(&temporary, &destination) {
            Ok(()) => Ok(()),
            Err(_) if destination.is_file() => {
                let _ = std::fs::remove_file(&temporary);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
