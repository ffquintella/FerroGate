//! Windows Service Control Manager (SCM) integration for the `mia` daemon.
//!
//! `mia` is `#![forbid(unsafe_code)]` and the `windows-service` service-main
//! macro expands to `unsafe` glue, so the SCM dispatcher and registration live
//! here (this crate is the project's Windows FFI boundary). `mia` supplies its
//! daemon entry point and a stop hook via [`ServiceHooks`]; the install /
//! uninstall / start / stop helpers drive the SCM so `Restart-Service mia`
//! works once the agent is installed.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Context as _;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// The Windows service name (`Restart-Service mia`, `sc.exe ... mia`).
pub const SERVICE_NAME: &str = "mia";

/// `mia` runs as its own process, not a shared-process service host.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Daemon and stop hooks the `mia` binary hands to the dispatcher. Plain `fn`
/// pointers (not closures) so they can sit in a `static` for the SCM-generated
/// entry point to reach.
#[derive(Clone, Copy)]
pub struct ServiceHooks {
    /// Run the daemon to completion and return a process exit code (0 = ok).
    /// Must return after `request_stop` is invoked.
    pub run: fn() -> i32,
    /// Invoked from the SCM control thread to ask the daemon to stop.
    pub request_stop: fn(),
}

static HOOKS: OnceLock<ServiceHooks> = OnceLock::new();

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM dispatcher. This is the target of `mia service run`,
/// which is the command the registered service launches. Blocks until the
/// service stops.
pub fn run_dispatcher(hooks: ServiceHooks) -> anyhow::Result<()> {
    HOOKS
        .set(hooks)
        .map_err(|_| anyhow::anyhow!("service hooks already initialized"))?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("starting the service control dispatcher (is mia running under the SCM?)")?;
    Ok(())
}

/// The SCM calls this (via the generated `ffi_service_main`) on a dedicated
/// thread once the service starts.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        // There is no console under the SCM; the daemon logs to its own file.
        // This is a last-resort surface for a dispatcher-level failure.
        eprintln!("mia service control handler failed: {e:#}");
    }
}

/// Build a [`ServiceStatus`] in `state`, accepting `controls`, reporting `code`.
fn status(state: ServiceState, controls: ServiceControlAccept, code: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: controls,
        exit_code: code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    let hooks = *HOOKS.get().context("service hooks not initialized")?;

    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            (hooks.request_stop)();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .context("registering the service control handler")?;

    status_handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::Win32(0),
        ))
        .context("reporting service state Running")?;

    let code = (hooks.run)();

    let exit_code = if code == 0 {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(u32::try_from(code).unwrap_or(1))
    };
    status_handle
        .set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
        ))
        .context("reporting service state Stopped")?;
    Ok(())
}

/// Register the `mia` Windows service (auto-start, LocalSystem) so the SCM
/// launches `"<exe>" service run`. Requires Administrator rights.
pub fn install(exe_path: &Path, display_name: &str, description: &str) -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the service control manager (run as Administrator)")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(display_name),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.to_path_buf(),
        launch_arguments: vec![OsString::from("service"), OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating the mia service (is it already installed?)")?;
    service
        .set_description(description)
        .context("setting the mia service description")?;
    Ok(())
}

/// Stop (best-effort) and delete the `mia` service. Requires Administrator
/// rights.
pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service control manager (run as Administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("opening the mia service (is it installed?)")?;

    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            // Ignore the stop error: a service that is already stopping, or
            // refuses to stop, must not block deletion (it is removed on the
            // next reboot in that case).
            let _ = service.stop();
        }
    }
    service.delete().context("deleting the mia service")?;
    Ok(())
}

/// Start the installed `mia` service. Requires Administrator rights.
pub fn start() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service control manager (run as Administrator)")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .context("opening the mia service (is it installed?)")?;
    let no_args: [&OsStr; 0] = [];
    service.start(&no_args).context("starting the mia service")?;
    Ok(())
}

/// Stop the running `mia` service. Requires Administrator rights.
pub fn stop() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service control manager (run as Administrator)")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP)
        .context("opening the mia service (is it installed?)")?;
    service.stop().context("stopping the mia service")?;
    Ok(())
}
