use super::*;
use nix::fcntl::{Flock, FlockArg};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Instant;

const RETRY_INTERVAL: Duration = Duration::from_secs(30);
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(300);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BATCH: usize = 8;
const BATCH_BUDGET: Duration = Duration::from_secs(10);

pub(crate) struct DeliveryWorker {
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl DeliveryWorker {
    // Start only in the supervisor parent after fork.
    pub(crate) fn start() -> Result<Option<Self>> {
        if queued_count()? == 0 && load_state()?.is_none() {
            return Ok(None);
        }
        let (stop, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("nono-audit-delivery".into())
            .spawn(move || run(receiver))
            .map_err(|error| NonoError::Snapshot(format!("start audit delivery: {error}")))?;
        Ok(Some(Self {
            stop,
            thread: Some(thread),
        }))
    }
}

impl Drop for DeliveryWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(stop: Receiver<()>) {
    let mut delay = RETRY_INTERVAL;
    let mut cursor = None;
    loop {
        if stop.try_recv() != Err(mpsc::TryRecvError::Empty) {
            return;
        }
        let failed = match retry_batch(&stop, &mut cursor) {
            Ok(Some(failed)) => failed,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!("Audit uploads remain queued; run `nono audit sync`: {error}");
                true
            }
        };
        let wait = if failed { delay } else { RETRY_INTERVAL };
        delay = retry_delay(delay, failed);
        if stop.recv_timeout(wait) != Err(mpsc::RecvTimeoutError::Timeout) {
            return;
        }
    }
}

fn retry_delay(previous: Duration, failed: bool) -> Duration {
    if failed {
        previous.saturating_mul(2).min(MAX_RETRY_INTERVAL)
    } else {
        RETRY_INTERVAL
    }
}

pub(super) fn retry_batch(
    stop: &Receiver<()>,
    cursor: &mut Option<PathBuf>,
) -> Result<Option<bool>> {
    let started = Instant::now();
    let active = match load_state() {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!("Cannot load current enrollment for legacy audit uploads: {error}");
            None
        }
    };
    let mut failed = false;
    let mut paths = queued_paths()?;
    if let Some(last) = cursor {
        let next = paths.partition_point(|path| path <= last);
        paths.rotate_left(next);
    }
    for path in paths.into_iter().take(MAX_BATCH) {
        if stop.try_recv() != Err(mpsc::TryRecvError::Empty) {
            return Ok(None);
        }
        if started.elapsed() >= BATCH_BUDGET {
            break;
        }
        *cursor = Some(path.clone());
        let result = deliver_path(&path, active.as_ref(), REQUEST_TIMEOUT);
        if let Err(error) = result {
            failed = true;
            tracing::warn!("Audit upload remains queued: {error}");
        }
    }
    Ok(Some(failed))
}

pub(super) fn lock_queue(blocking: bool) -> Result<Option<Flock<File>>> {
    let dir = crate::state_paths::user_state_dir()?;
    fs::create_dir_all(&dir).map_err(|source| NonoError::ConfigWrite {
        path: dir.clone(),
        source,
    })?;
    let path = dir.join("audit-delivery.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|source| NonoError::ConfigWrite {
            path: path.clone(),
            source,
        })?;
    match Flock::lock(
        file,
        if blocking {
            FlockArg::LockExclusive
        } else {
            FlockArg::LockExclusiveNonblock
        },
    ) {
        Ok(lock) => Ok(Some(lock)),
        Err((_, nix::errno::Errno::EWOULDBLOCK)) if !blocking => Ok(None),
        Err((_, errno)) => Err(NonoError::ConfigWrite {
            path,
            source: std::io::Error::from(errno),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_back_off_and_recover() {
        assert_eq!(retry_delay(RETRY_INTERVAL, true), Duration::from_secs(60));
        assert_eq!(retry_delay(MAX_RETRY_INTERVAL, true), MAX_RETRY_INTERVAL);
        assert_eq!(retry_delay(MAX_RETRY_INTERVAL, false), RETRY_INTERVAL);
    }
}
