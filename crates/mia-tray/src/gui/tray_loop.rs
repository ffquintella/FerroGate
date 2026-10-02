//! The tray process's event loop: GTK on Linux (the StatusNotifierItem menu
//! lives in a GTK main loop), winit on macOS and Windows (an `NSApplication`
//! run loop / a Win32 message pump). Both just call
//! [`TrayController::tick`] every [`TICK`].

use std::process::ExitCode;
use std::time::Duration;

use super::tray::{Flow, TrayController};
use crate::i18n::Lang;

/// How often the controller runs.
const TICK: Duration = Duration::from_millis(250);

#[cfg(target_os = "linux")]
pub(crate) fn run(lang: Lang) -> ExitCode {
    use std::cell::RefCell;
    use std::rc::Rc;

    if let Err(e) = gtk::init() {
        tracing::error!(error = %e, "GTK could not be initialised (no display?)");
        return ExitCode::FAILURE;
    }
    let controller = match TrayController::new(lang) {
        Ok(c) => Rc::new(RefCell::new(c)),
        Err(e) => {
            tracing::error!(error = %e, "could not create the tray icon");
            return ExitCode::FAILURE;
        }
    };
    let ticking = Rc::clone(&controller);
    gtk::glib::timeout_add_local(TICK, move || {
        if ticking.borrow_mut().tick() == Flow::Quit {
            gtk::main_quit();
            gtk::glib::ControlFlow::Break
        } else {
            gtk::glib::ControlFlow::Continue
        }
    });
    gtk::main();
    drop(controller);
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run(lang: Lang) -> ExitCode {
    use winit::application::ApplicationHandler;
    use winit::event::{StartCause, WindowEvent};
    use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
    use winit::window::WindowId;

    struct App {
        lang: Lang,
        controller: Option<TrayController>,
        failed: bool,
    }

    impl ApplicationHandler for App {
        fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
            // The tray icon may only be created once the platform
            // application has finished launching, i.e. on `Init`.
            if matches!(cause, StartCause::Init) && self.controller.is_none() {
                match TrayController::new(self.lang) {
                    Ok(c) => self.controller = Some(c),
                    Err(e) => {
                        tracing::error!(error = %e, "could not create the tray icon");
                        self.failed = true;
                        event_loop.exit();
                        return;
                    }
                }
            }
            if let Some(c) = self.controller.as_mut() {
                if c.tick() == Flow::Quit {
                    event_loop.exit();
                    return;
                }
            }
            event_loop.set_control_flow(ControlFlow::WaitUntil(std::time::Instant::now() + TICK));
        }

        fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

        fn window_event(&mut self, _: &ActiveEventLoop, _: WindowId, _: WindowEvent) {}
    }

    let mut builder = EventLoop::builder();
    #[cfg(target_os = "macos")]
    {
        // A menu-bar extra: no Dock icon, no app menu.
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS as _};
        builder.with_activation_policy(ActivationPolicy::Accessory);
    }
    let event_loop = match builder.build() {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "could not start the event loop");
            return ExitCode::FAILURE;
        }
    };
    let mut app = App {
        lang,
        controller: None,
        failed: false,
    };
    if let Err(e) = event_loop.run_app(&mut app) {
        tracing::error!(error = %e, "the event loop failed");
        return ExitCode::FAILURE;
    }
    if app.failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
