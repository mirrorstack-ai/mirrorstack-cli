//! Bounded subprocess execution for release tools and builds.
//!
//! Process groups/jobs clean up ordinary tool descendants, while independent
//! I/O deadlines keep the CLI itself bounded. This is not a hostile-process
//! sandbox: on Unix a deliberate same-UID child can escape its group with
//! `setsid`; release tooling and the local publisher remain trusted.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};

const CLEANUP_GRACE: Duration = Duration::from_secs(2);
const MAX_STDIN_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(super) struct ProcessSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: BTreeMap<OsString, OsString>,
    pub env_remove: BTreeSet<OsString>,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
}

impl ProcessSpec {
    pub(super) fn new(program: impl Into<OsString>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: cwd.into(),
            env: BTreeMap::new(),
            env_remove: BTreeSet::new(),
            stdin: Vec::new(),
            timeout: Duration::from_secs(120),
            stdout_limit: 1024 * 1024,
            stderr_limit: 256 * 1024,
        }
    }

    pub(super) fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub(super) fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub(super) fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        let key = key.into();
        self.env_remove.remove(&key);
        self.env.insert(key, value.into());
        self
    }

    pub(super) fn env_remove(mut self, key: impl Into<OsString>) -> Self {
        let key = key.into();
        self.env.remove(&key);
        self.env_remove.insert(key);
        self
    }

    pub(super) fn stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = stdin;
        self
    }

    pub(super) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub(super) fn limits(mut self, stdout: usize, stderr: usize) -> Self {
        self.stdout_limit = stdout;
        self.stderr_limit = stderr;
        self
    }
}

#[derive(Debug)]
pub(super) struct ProcessOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(super) trait ProcessRunner {
    fn run(&self, spec: &ProcessSpec) -> Result<ProcessOutput>;
}

pub(super) struct SystemRunner;

impl ProcessRunner for SystemRunner {
    fn run(&self, spec: &ProcessSpec) -> Result<ProcessOutput> {
        let display = command_name(&spec.program);
        if spec.stdin.len() > MAX_STDIN_BYTES {
            return Err(anyhow!(
                "release candidate: `{display}` stdin exceeds {MAX_STDIN_BYTES} bytes"
            ));
        }
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .current_dir(&spec.cwd)
            .envs(&spec.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in &spec.env_remove {
            command.env_remove(key);
        }
        configure_containment(&mut command)?;
        let started = Instant::now();
        let child = command.spawn().map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                anyhow!("release candidate: required tool `{display}` was not found on PATH")
            }
            _ => anyhow!("release candidate: start `{display}`: {error}"),
        })?;
        // From this point every `?` and early return runs the same bounded
        // tree cleanup. No error path may synchronously wait on a child or on
        // a pipe reader whose handle was inherited by a descendant.
        let mut process = SpawnedProcess::new(child);
        process.containment = Some(
            attach_containment(&process.child)
                .with_context(|| format!("release candidate: contain `{display}` process tree"))?,
        );

        let stdout = process
            .child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("release candidate: `{display}` stdout was unavailable"))?;
        let stderr = process
            .child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("release candidate: `{display}` stderr was unavailable"))?;
        let stdout_limit = spec.stdout_limit;
        let stderr_limit = spec.stderr_limit;
        let stdout_reader = spawn_reader(stdout, stdout_limit);
        let stderr_reader = spawn_reader(stderr, stderr_limit);

        // Drain output before supplying input. A tool is allowed to write a
        // full stdout/stderr pipe before it reads stdin; synchronous input
        // first would deadlock outside the timeout. The writer is bounded and
        // independently observed by the same process deadline.
        let mut stdin_writer = if spec.stdin.is_empty() {
            // EOF is part of the SDK manifest-tool protocol even for empty
            // input.
            drop(process.child.stdin.take());
            None
        } else {
            let stdin =
                process.child.stdin.take().ok_or_else(|| {
                    anyhow!("release candidate: `{display}` stdin was unavailable")
                })?;
            Some(spawn_writer(stdin, spec.stdin.clone()))
        };

        let deadline = started + spec.timeout;
        let status = loop {
            if let Some(receiver) = stdin_writer.as_ref() {
                match receiver.try_recv() {
                    Ok(result) => {
                        result.with_context(|| {
                            format!("release candidate: write `{display}` stdin")
                        })?;
                        stdin_writer = None;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err(anyhow!(
                            "release candidate: `{display}` stdin writer stopped unexpectedly"
                        ));
                    }
                }
            }
            match process
                .child
                .try_wait()
                .with_context(|| format!("release candidate: wait for `{display}`"))?
            {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    return Err(anyhow!(
                        "release candidate: `{display}` exceeded its {}s timeout",
                        spec.timeout.as_secs()
                    ));
                }
                None => thread::sleep(Duration::from_millis(20)),
            }
        };

        // A successful one-shot tool must not leave background descendants.
        // Closing/killing the containment before joining the pipe readers also
        // guarantees an inherited stdout/stderr handle cannot hang this
        // supposedly bounded runner after the direct child exits.
        process.terminate_tree();

        let drain_deadline = Instant::now() + CLEANUP_GRACE;
        if let Some(receiver) = stdin_writer {
            collect_writer(receiver, drain_deadline, &display)?;
        }
        let stdout = collect_reader(stdout_reader, drain_deadline, &display, "stdout")?;
        let stderr = collect_reader(stderr_reader, drain_deadline, &display, "stderr")?;
        if stdout.exceeded {
            return Err(anyhow!(
                "release candidate: `{display}` stdout exceeded {} bytes",
                spec.stdout_limit
            ));
        }
        if stderr.exceeded {
            return Err(anyhow!(
                "release candidate: `{display}` stderr exceeded {} bytes",
                spec.stderr_limit
            ));
        }
        Ok(ProcessOutput {
            success: status.success(),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }
}

struct SpawnedProcess {
    child: std::process::Child,
    containment: Option<ProcessContainment>,
    terminated: bool,
}

impl SpawnedProcess {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            containment: None,
            terminated: false,
        }
    }

    fn terminate_tree(&mut self) {
        if self.terminated {
            return;
        }
        if let Some(containment) = self.containment.as_ref() {
            terminate_containment(containment, self.child.id());
        }
        // On Windows, dropping the kill-on-close JobObject is what performs
        // tree termination. On Unix the process-group signal above handles
        // cooperative descendants; kill is a direct-child backstop.
        let _ = self.containment.take();
        let _ = self.child.kill();
        self.terminated = true;
    }

    fn reap_bounded(&mut self) {
        let deadline = Instant::now() + CLEANUP_GRACE;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => return,
                Ok(None) => thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

impl Drop for SpawnedProcess {
    fn drop(&mut self) {
        self.terminate_tree();
        self.reap_bounded();
    }
}

#[cfg(unix)]
fn configure_containment(command: &mut Command) -> Result<()> {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    Ok(())
}

#[cfg(not(unix))]
fn configure_containment(command: &mut Command) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

        // The stdlib cannot attach a JobObject at CreateProcess time. Start
        // the only thread suspended, attach the process to a kill-on-close
        // job, and resume it only after containment is proven. This closes
        // the spawn -> AssignProcessToJobObject window in which a child could
        // otherwise create an escaping descendant.
        command.creation_flags(CREATE_SUSPENDED);
    }
    Ok(())
}

#[cfg(windows)]
struct ProcessContainment(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for ProcessContainment {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // SAFETY: the tuple owns the job handle exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(not(windows))]
struct ProcessContainment;

#[cfg(windows)]
fn attach_containment(child: &std::process::Child) -> Result<ProcessContainment> {
    use std::mem::{MaybeUninit, size_of};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    // SAFETY: null attributes/name request an unnamed job with defaults.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(std::io::Error::last_os_error()).context("create Windows job object");
    }
    let information = MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed();
    // SAFETY: zero is a valid base for this POD Win32 structure.
    let mut information = unsafe { information.assume_init() };
    information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `job` is live and `information` has the exact structure/size
    // required by JobObjectExtendedLimitInformation.
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        let error = std::io::Error::last_os_error();
        // SAFETY: `job` is still owned here.
        unsafe { CloseHandle(job) };
        return Err(error).context("configure Windows job object");
    }
    // SAFETY: the child handle stays live for this call and `job` is valid.
    let assigned = unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) };
    if assigned == 0 {
        let error = std::io::Error::last_os_error();
        // SAFETY: `job` is still owned here.
        unsafe { CloseHandle(job) };
        return Err(error).context("assign process to Windows job object");
    }
    if let Err(error) = resume_suspended_process(child.id()) {
        // Closing a configured, assigned job kills the still-suspended child.
        // The caller also waits it before returning the error.
        unsafe { CloseHandle(job) };
        return Err(error).context("resume job-contained Windows process");
    }
    Ok(ProcessContainment(job))
}

#[cfg(windows)]
fn resume_suspended_process(process_id: u32) -> Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    // SAFETY: flags and process id follow the ToolHelp contract.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("snapshot Windows threads");
    }

    let result = (|| {
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..THREADENTRY32::default()
        };
        // SAFETY: snapshot is valid and entry points to the sized structure.
        let mut found = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while found {
            if entry.th32OwnerProcessID == process_id {
                // The process was created suspended, so this is its sole
                // initial thread and no user code has run yet.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    return Err(std::io::Error::last_os_error())
                        .context("open suspended Windows process thread");
                }
                // SAFETY: thread is a live handle with suspend/resume access.
                let previous = unsafe { ResumeThread(thread) };
                // SAFETY: this scope owns thread exactly once.
                unsafe { CloseHandle(thread) };
                if previous == u32::MAX {
                    return Err(std::io::Error::last_os_error())
                        .context("resume suspended Windows process thread");
                }
                return Ok(());
            }
            // SAFETY: same valid snapshot/entry contract as Thread32First.
            found = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        Err(anyhow!(
            "suspended Windows process {process_id} had no discoverable initial thread"
        ))
    })();
    // SAFETY: this scope owns snapshot exactly once.
    unsafe { CloseHandle(snapshot) };
    result
}

#[cfg(not(windows))]
fn attach_containment(_child: &std::process::Child) -> Result<ProcessContainment> {
    Ok(ProcessContainment)
}

#[cfg(unix)]
fn terminate_containment(_containment: &ProcessContainment, child_id: u32) {
    // The child created its own process group with pgid == pid. A negative
    // target signals the whole group, including descendants that inherited a
    // pipe after their direct parent exited.
    if let Ok(group) = i32::try_from(child_id) {
        // SAFETY: kill has no memory-safety preconditions; ESRCH is expected
        // when the group already exited.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
}

#[cfg(windows)]
fn terminate_containment(_containment: &ProcessContainment, _child_id: u32) {
    // Dropping the KILL_ON_JOB_CLOSE handle performs the termination.
}

#[cfg(not(any(unix, windows)))]
fn terminate_containment(_containment: &ProcessContainment, _child_id: u32) {}

struct CappedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn spawn_reader(
    reader: impl Read + Send + 'static,
    limit: usize,
) -> Receiver<std::io::Result<CappedRead>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(read_capped(reader, limit));
    });
    receiver
}

fn spawn_writer(
    mut writer: impl Write + Send + 'static,
    bytes: Vec<u8>,
) -> Receiver<std::io::Result<()>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = writer.write_all(&bytes);
        drop(writer);
        let _ = sender.send(result);
    });
    receiver
}

fn collect_writer(
    receiver: Receiver<std::io::Result<()>>,
    deadline: Instant,
    display: &str,
) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(result) => result.with_context(|| format!("release candidate: write `{display}` stdin")),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(anyhow!(
            "release candidate: `{display}` stdin did not close within {}s after process-tree cleanup",
            CLEANUP_GRACE.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow!(
            "release candidate: `{display}` stdin writer stopped unexpectedly"
        )),
    }
}

fn collect_reader(
    receiver: Receiver<std::io::Result<CappedRead>>,
    deadline: Instant,
    display: &str,
    stream: &str,
) -> Result<CappedRead> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(result) => {
            result.with_context(|| format!("release candidate: read `{display}` {stream}"))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(anyhow!(
            "release candidate: `{display}` {stream} did not close within {}s after process-tree cleanup",
            CLEANUP_GRACE.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow!(
            "release candidate: `{display}` {stream} reader stopped unexpectedly"
        )),
    }
}

fn read_capped(mut reader: impl Read, limit: usize) -> std::io::Result<CappedRead> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut exceeded = false;
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let keep = remaining.min(read);
        bytes.extend_from_slice(&chunk[..keep]);
        exceeded |= keep < read;
        // Keep draining after the cap so a chatty child cannot deadlock on a
        // full pipe while the parent waits to terminate it.
    }
    Ok(CappedRead { bytes, exceeded })
}

fn command_name(program: &OsStr) -> String {
    Path::new(program)
        .file_name()
        .unwrap_or(program)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_reader_keeps_only_the_limit() {
        let read = read_capped(&b"abcdef"[..], 3).unwrap();
        assert_eq!(read.bytes, b"abc");
        assert!(read.exceeded);
    }

    #[test]
    fn system_runner_closes_stdin_and_captures_output() {
        #[cfg(unix)]
        let spec = ProcessSpec::new("sh", ".")
            .args(["-c", "read value; printf '%s' \"$value\""])
            .stdin(b"hello\n".to_vec());
        #[cfg(windows)]
        let spec = ProcessSpec::new("cmd", ".")
            .args(["/C", "set /p value=& call echo|set /p=%%value%%"])
            .stdin(b"hello\r\n".to_vec());
        let output = SystemRunner.run(&spec).unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, b"hello");
    }

    #[cfg(unix)]
    #[test]
    fn output_and_input_are_drained_concurrently_under_one_deadline() {
        let spec = ProcessSpec::new("sh", ".")
            .args([
                "-c",
                "dd if=/dev/zero bs=4096 count=32 2>/dev/null; cat >/dev/null",
            ])
            .stdin(vec![b'x'; MAX_STDIN_BYTES])
            .timeout(Duration::from_secs(2))
            .limits(256 * 1024, 16 * 1024);
        let output = SystemRunner.run(&spec).unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.len(), 128 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn inherited_pipe_descendant_cannot_outlive_the_bounded_runner() {
        let started = Instant::now();
        let spec = ProcessSpec::new("sh", ".")
            .args(["-c", "sleep 30 &"])
            .timeout(Duration::from_secs(2));
        let output = SystemRunner.run(&spec).unwrap();
        assert!(output.success);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "runner waited on the background child's inherited pipe"
        );
    }

    #[cfg(unix)]
    #[test]
    fn timeout_reaps_an_inherited_pipe_process_tree_without_blocking() {
        let started = Instant::now();
        let spec = ProcessSpec::new("sh", ".")
            .args(["-c", "sleep 30 & wait"])
            .timeout(Duration::from_millis(100));
        let error = SystemRunner.run(&spec).unwrap_err();
        assert!(error.to_string().contains("timeout"), "{error:#}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout blocked while reaping inherited pipes"
        );
    }
}
