//! A background job whose result the UI thread collects without blocking.

use std::sync::mpsc;

/// One background computation.
pub(crate) struct Job<T> {
    rx: mpsc::Receiver<T>,
}

/// What [`Job::poll`] found.
pub(crate) enum Polled<T> {
    /// Still running.
    Pending,
    /// Finished with a value.
    Ready(T),
    /// The worker died without a result (a panic); already logged.
    Lost,
}

impl<T: Send + 'static> Job<T> {
    /// Run `f` on a new thread; `ctx` (if any) is asked to repaint when done.
    pub(crate) fn spawn(
        ctx: Option<eframe::egui::Context>,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });
        Self { rx }
    }

    /// Collect the result if it is there.
    pub(crate) fn poll(&mut self) -> Polled<T> {
        match self.rx.try_recv() {
            Ok(v) => Polled::Ready(v),
            Err(mpsc::TryRecvError::Empty) => Polled::Pending,
            Err(mpsc::TryRecvError::Disconnected) => {
                tracing::error!("a background job ended without a result");
                Polled::Lost
            }
        }
    }
}

/// Poll an optional job slot: returns the value (clearing the slot) once it
/// is ready, `None` while pending or empty. A lost job clears the slot too.
pub(crate) fn take<T: Send + 'static>(slot: &mut Option<Job<T>>) -> Option<T> {
    let job = slot.as_mut()?;
    match job.poll() {
        Polled::Pending => None,
        Polled::Ready(v) => {
            *slot = None;
            Some(v)
        }
        Polled::Lost => {
            *slot = None;
            None
        }
    }
}
