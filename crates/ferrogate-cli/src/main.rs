//! `FerroGate` — CLI bootstrapped by ironroot.

// --- default rotating-file logger (10MB, keep 5) -----------------------
fn init_logging(app_name: &str) -> tracing_appender::non_blocking::WorkerGuard {
    use file_rotate::{compression::Compression, suffix::AppendCount, ContentLimit, FileRotate};
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    std::fs::create_dir_all("logs").expect("create logs dir");
    let path = std::path::Path::new("logs").join(format!("{app_name}.log"));
    let rotator = FileRotate::new(
        path,
        AppendCount::new(5),
        ContentLimit::Bytes(10 * 1024 * 1024),
        Compression::None,
        #[cfg(unix)]
        None,
    );
    let (writer, guard) = tracing_appender::non_blocking(rotator);
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_ansi(false).with_writer(writer))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();
    guard
}

fn main() {
    let _log_guard = init_logging("FerroGate");
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "FerroGate starting");
        println!("FerroGate v{}", env!("CARGO_PKG_VERSION"));
        println!("usage: FerroGate <command> [args...]");
        return;
    }
    match args[0].as_str() {
        "hello" => {
            tracing::info!(
                target = args.get(1).map(String::as_str).unwrap_or("world"),
                "greet"
            );
            println!(
                "hello, {}!",
                args.get(1).map(String::as_str).unwrap_or("world")
            );
        }
        other => {
            tracing::warn!(command = other, "unknown command");
            eprintln!("unknown command: {other}");
        }
    }
}

pub fn add(a: i64, b: i64) -> i64 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_works() {
        assert_eq!(add(2, 3), 5);
    }
}
