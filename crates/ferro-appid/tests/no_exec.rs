//! F19 §4.1 "never execute": no source file of `ferro-appid` may name a
//! process-spawning API. (`clippy.toml` also makes `std::process::Command`
//! a lint error; this test catches what a lint configuration could miss,
//! such as a new module or a re-export.)

use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "std::process",
    "process::Command",
    "Command::new",
    "CommandExt",
    ".spawn(",
    "execv",
    "posix_spawn",
    "CreateProcess",
    "ShellExecute",
    "WinExec",
];

fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_source_file_can_spawn_a_process() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    assert!(files.len() >= 10, "found the sources: {files:?}");
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "{} mentions {needle}",
                file.display()
            );
        }
    }
}

#[test]
fn the_lint_configuration_forbids_command() {
    let toml =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("clippy.toml")).unwrap();
    assert!(toml.contains("std::process::Command"));
}
