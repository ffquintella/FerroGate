//! Build script: embed the FerroGate icon into the Windows executables, so
//! Explorer, Task Manager and the Services snap-in's process view show the
//! product icon instead of the generic one. No-op on other targets.

fn main() {
    if let Err(e) = ferro_winres::embed_icon_for_windows_bins("dist/icons/ferrogate-mia.ico") {
        panic!("embedding the Windows icon failed: {e}");
    }
}
