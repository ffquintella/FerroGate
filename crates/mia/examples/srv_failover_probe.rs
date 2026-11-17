//! Failover probe for the Docker behaviour tests (`docker/failover-test`).
//!
//! Resolves a CMIS SRV name with the production [`mia::endpoint::CmisResolver`]
//! and, once per interval, makes one real RPC (`GetEnrollmentKey`) through
//! [`CmisResolver::call`](mia::endpoint::CmisResolver::call). Prints one line per
//! attempt, which the test harness parses:
//!
//! ```text
//! OK <unix_ms> https://cmis2.fg.test:8443 <elapsed_ms>
//! ERR <unix_ms> <message> <elapsed_ms>
//! ```
//!
//! Usage: `srv_failover_probe <srv-name> <spki-pin-hex> [interval-ms]`.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mia::config::CmisConfig;
use mia::endpoint::CmisResolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(srv), Some(pin)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: srv_failover_probe <srv-name> <spki-pin-hex> [interval-ms]");
    };
    let interval = Duration::from_millis(args.next().and_then(|v| v.parse().ok()).unwrap_or(1000));
    let resolver = CmisResolver::from_config(&CmisConfig {
        endpoint: None,
        srv: Some(srv),
        spki_pin: Some(pin),
    })?
    .ok_or_else(|| anyhow::anyhow!("cmis not configured"))?;

    loop {
        let started = Instant::now();
        let outcome = resolver
            .call(
                |mut c| async move { mia::client::fetch_enrollment_key(&mut c).await.map(|_| ()) },
            )
            .await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let ms = started.elapsed().as_millis();
        match outcome {
            Ok((endpoint, ())) => println!("OK {now} {endpoint} {ms}"),
            Err(e) => println!("ERR {now} {} {ms}", format!("{e:#}").replace('\n', " ")),
        }
        tokio::time::sleep(interval).await;
    }
}
