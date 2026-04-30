//! Best-effort browser opener. Callers should always print the URL
//! alongside calling [`open`] so the user can copy-paste if auto-open
//! fails (headless env, SSH, browser crashed, etc.).

use std::io;

pub fn open(url: &str) -> io::Result<()> {
    ::open::that(url)
}
