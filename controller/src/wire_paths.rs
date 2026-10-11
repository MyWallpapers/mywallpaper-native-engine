use std::time::Duration;

pub(crate) const PIPE_IO_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const PIPE_NAME_CAPACITY: usize = 192;
const PIPE_PREFIX: &str = r"\\.\pipe\";

pub(crate) fn canonical_pipe_path(name: &str) -> Result<String, String> {
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
