//! `ferrogate-tui` — the server administration TUI (feature F21).
//!
//! Thin by design: parse the few flags, load the configuration (refusing to
//! start without an SPKI pin), start the client task, own the terminal and run
//! the event loop. Everything else lives in the library (`ferrogate_tui`).
//!
//! Terminal hygiene: raw mode and the alternate screen, restored on normal
//! exit, `Ctrl-C`, `SIGTERM`/`SIGHUP` and panic (panic hook); the screen is
//! cleared on lock and on exit so the scroll-back keeps no records. No logging.

#![forbid(unsafe_code)]

use std::io::Stdout;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ferrogate_tui::app::{App, Msg};
use ferrogate_tui::client::{self, ClientConfig, ClientHandle};
use ferrogate_tui::config::{self, ConfigError};
use ferrogate_tui::fatal;
use ferrogate_tui::input::{self, Key};
use ferrogate_tui::screens;
use ferrogate_tui::secret::Secret;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event};
use ratatui::crossterm::terminal::{
    self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::{cursor, execute};
use ratatui::Terminal;
use tokio::sync::mpsc;
use zeroize::Zeroize as _;

/// How long a quit waits for the server-side logout.
const LOGOUT_WAIT: Duration = Duration::from_secs(3);

fn usage() -> &'static str {
    "ferrogate-tui — FerroGate server administration TUI (F21)\n\
     \n\
     usage: ferrogate-tui [--config <path>] [--monochrome]\n\
     \x20      ferrogate-tui --help | --version\n\
     \n\
     Signs in to the CMIS admin listener with username, password and a TOTP\n\
     code, then lists, searches, approves, denies, edits, revokes and adds\n\
     applications. Every action is an admin gRPC call authorised by CMIS.\n\
     \n\
     configuration (no secrets):\n\
     \x20 $XDG_CONFIG_HOME/ferrogate/admin.toml, else /etc/ferrogate/admin.toml\n\
     \x20   endpoint = \"https://127.0.0.1:8444\"     explicit port required\n\
     \x20   spki_pins = [\"<sha384-hex>\"]       required (no trust on first use)\n\
     \x20   device_token_path = \"\"               default $XDG_STATE_HOME/ferrogate/device-token\n\
     \x20   refresh_secs = 30                      list auto-refresh, 0 = off\n\
     \x20 FERROGATE_ADMIN_ENDPOINT, FERROGATE_ADMIN_SPKI_PIN override the file.\n\
     \x20 NO_COLOR (or --monochrome) draws without colours. Minimum 80x24.\n\
     \n\
     Ctrl-L locks, q quits (signing out), ? shows the key map."
}

/// What the input thread reports.
enum Input {
    Key(Key),
    Paste(Secret),
    Redraw,
}

fn ferro_crypto_pin_hex(pin: &ferro_crypto::pin::SpkiPin) -> String {
    pin.to_hex()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Put the terminal back: raw mode off, screen and scroll-back cleared, main
/// screen restored. Safe to call more than once (panic hook and drop).
fn restore_terminal() {
    let _ = terminal::disable_raw_mode();
    let mut out = std::io::stdout();
    let _ = execute!(
        out,
        Clear(ClearType::All),
        Clear(ClearType::Purge),
        DisableBracketedPaste,
        LeaveAlternateScreen,
        cursor::Show
    );
}

/// Owns the terminal; restores it when dropped.
struct TerminalGuard(Terminal<CrosstermBackend<Stdout>>);

impl TerminalGuard {
    fn enter() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut out = std::io::stdout();
        if let Err(e) = execute!(
            out,
            EnterAlternateScreen,
            EnableBracketedPaste,
            cursor::Hide
        ) {
            restore_terminal();
            return Err(e);
        }
        Terminal::new(CrosstermBackend::new(std::io::stdout()))
            .map(Self)
            .inspect_err(|_| restore_terminal())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Read terminal events on a plain thread and forward them.
fn spawn_input(tx: mpsc::Sender<Input>) {
    std::thread::spawn(move || {
        while !tx.is_closed() {
            match event::poll(Duration::from_millis(200)) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => return,
            }
            let msg = match event::read() {
                Ok(Event::Key(k)) => match input::from_crossterm(k) {
                    Some(key) => Input::Key(key),
                    None => continue,
                },
                Ok(Event::Paste(mut text)) => {
                    let mut s = Secret::new();
                    for c in text.chars() {
                        s.push(c);
                    }
                    text.zeroize();
                    Input::Paste(s)
                }
                Ok(Event::Resize(..)) => Input::Redraw,
                Ok(_) => continue,
                Err(_) => return,
            };
            if tx.blocking_send(msg).is_err() {
                return;
            }
        }
    });
}

/// Resolves when the process is asked to stop (SIGTERM, SIGHUP, SIGINT).
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut term), Ok(mut hup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) else {
            std::future::pending::<()>().await;
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = hup.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Why the loop stopped drawing before a normal quit.
enum Failure {
    /// The terminal cannot be written any more (SSH disconnect, SIGHUP).
    Terminal(std::io::Error),
    /// A panic, or a task the UI depends on stopped.
    Internal(&'static str),
}

/// Stop drawing for good: put the terminal back now (a no-op after the
/// panic hook did it), wipe what is shown and end the session.
fn fail(app: &mut App, client: &ClientHandle, failure: &mut Option<Failure>, why: Failure) {
    if failure.is_some() {
        return;
    }
    if matches!(why, Failure::Internal(_)) {
        restore_terminal();
    }
    *failure = Some(why);
    dispatch(app, client, Msg::Key(Key::CtrlC));
}

#[allow(clippy::too_many_lines)] // the event loop, one arm per source.
async fn run(cfg: config::Config, monochrome: bool) -> anyhow::Result<()> {
    let pin = cfg
        .spki_pins
        .first()
        .map(ferro_crypto_pin_hex)
        .unwrap_or_default();
    let mut app = App::new(&cfg.endpoint, &pin, cfg.refresh_secs, monochrome);
    let (client, mut reply_rx) = client::spawn(ClientConfig {
        endpoint: cfg.endpoint.clone(),
        pins: cfg.spki_pins.clone(),
        device_token_path: cfg.device_token_path.clone(),
        connect_timeout: client::CONNECT_TIMEOUT,
        rpc_timeout: client::RPC_TIMEOUT,
    });

    // The hook raises the panic flag before restoring the terminal; the loop
    // below then never draws again.
    fatal::install(restore_terminal);
    let mut term = TerminalGuard::enter()?;
    let (input_tx, mut input_rx) = mpsc::channel::<Input>(client::CHANNEL_CAPACITY);
    spawn_input(input_tx);

    let start = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let stop = stop_signal();
    tokio::pin!(stop);
    let mut stopping = false;
    let mut input_open = true;
    let mut quit_deadline: Option<Instant> = None;
    app.update(Msg::Tick {
        mono: 0,
        unix: now_unix(),
    });
    // After a failure nothing is drawn; the session is still ended on the
    // server (the `Logout` goes out like any other quit's) before exiting.
    let mut failure: Option<Failure> = None;
    loop {
        if fatal::has_panicked() {
            fail(
                &mut app,
                &client,
                &mut failure,
                Failure::Internal("a panic"),
            );
        } else if client.is_closed() {
            fail(
                &mut app,
                &client,
                &mut failure,
                Failure::Internal("the client task stopped"),
            );
        }
        if failure.is_none() {
            if let Err(e) = term.0.draw(|f| screens::draw(&app, f)) {
                fail(&mut app, &client, &mut failure, Failure::Terminal(e));
            }
        }
        let msg = tokio::select! {
            input = input_rx.recv(), if input_open => match input {
                Some(Input::Key(k)) => Msg::Key(k),
                Some(Input::Paste(s)) => Msg::Paste(s),
                Some(Input::Redraw) => continue,
                None => {
                    // The input thread is gone (panic or terminal error).
                    input_open = false;
                    fail(&mut app, &client, &mut failure, Failure::Internal("the input reader stopped"));
                    continue;
                }
            },
            reply = reply_rx.recv() => {
                let Some(r) = reply else {
                    // Every client task is gone; their tokens were dropped
                    // (and wiped) with them.
                    fail(&mut app, &client, &mut failure, Failure::Internal("the client tasks stopped"));
                    break;
                };
                Msg::Reply(r)
            }
            _ = tick.tick() => Msg::Tick { mono: start.elapsed().as_secs(), unix: now_unix() },
            () = &mut stop, if !stopping => {
                stopping = true;
                Msg::Key(Key::CtrlC)
            }
        };
        dispatch(&mut app, &client, msg);
        if app.take_clear() && failure.is_none() {
            if let Err(e) = term.0.clear() {
                fail(&mut app, &client, &mut failure, Failure::Terminal(e));
            }
        }
        if app.is_quitting() && quit_deadline.is_none() {
            quit_deadline = Some(Instant::now() + LOGOUT_WAIT);
        }
        if app.should_quit() || quit_deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
    }
    // Ends the session (if not yet), closes the queue and waits briefly for
    // the tasks; anything still running is aborted and its token wiped. No
    // reply is read any more, so none may hold a task.
    drop(reply_rx);
    client.shutdown(LOGOUT_WAIT).await;
    drop(app);
    // Restores and clears again: also wipes any frame drawn after a panic.
    drop(term);
    match failure {
        None => Ok(()),
        Some(Failure::Terminal(e)) => Err(e.into()),
        Some(Failure::Internal(why)) => Err(anyhow::anyhow!(
            "internal error ({why}); the session was ended and the screen cleared"
        )),
    }
}

/// Apply `msg` and hand the resulting commands to the client: `Logout`
/// always goes through (the token is wiped at once); another command that
/// does not fit the queue is dropped with a notice. The UI never blocks on
/// the network.
fn dispatch(app: &mut App, client: &ClientHandle, msg: Msg) {
    for cmd in app.update(msg) {
        if !client.send(cmd) {
            app.command_dropped();
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path: Option<PathBuf> = None;
    let mut monochrome = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{}", usage());
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("ferrogate-tui {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--monochrome" => monochrome = true,
            "--config" => {
                let Some(p) = it.next() else {
                    eprintln!("--config needs a path\n\n{}", usage());
                    return ExitCode::from(2);
                };
                config_path = Some(PathBuf::from(p));
            }
            other => {
                eprintln!(
                    "unknown argument: {}\n\n{}",
                    ferrogate_tui::sanitize::truncate_end(other, 64),
                    usage()
                );
                return ExitCode::from(2);
            }
        }
    }
    let cfg = match config::load(config_path.as_deref()) {
        Ok(c) => c,
        Err(e @ ConfigError::NoPin) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("ferrogate-tui: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ferrogate-tui: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cfg, monochrome)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ferrogate-tui: {e}");
            ExitCode::FAILURE
        }
    }
}
