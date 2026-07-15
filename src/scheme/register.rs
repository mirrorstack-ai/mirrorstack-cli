//! Best-effort, idempotent registration of the per-OS URL-scheme handler.

/// Result of attempting to register the local `mirrorstack://` handler.
// Each compiled target can construct only its supported set of outcomes.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationOutcome {
    Registered,
    Unsupported,
    Failed(String),
}

/// Register the custom-scheme handler supported by the current platform.
pub fn register() -> RegistrationOutcome {
    #[cfg(target_os = "macos")]
    {
        super::macos::register()
    }
    #[cfg(target_os = "linux")]
    {
        super::linux::register()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        RegistrationOutcome::Unsupported
    }
}
