//! Build-Aufgaben von nrzNetwork – in Rust statt in Shell-Skripten, aufgerufen über den Alias in
//! `.cargo/config.toml`:
//!
//! ```text
//! cargo xtask ui                        Oberfläche bauen: ui/ → ui/dist/public (build.rs bettet sie ein)
//! cargo xtask serve [dx-Optionen]       Oberfläche mit Hot Reload (dx serve, http://localhost:8080)
//! cargo xtask dockerfile                Dockerfile ausgeben, z. B. `cargo xtask dockerfile > Dockerfile`
//! cargo xtask docker [Optionen]         docker buildx build mit diesem Dockerfile, z. B. `-t nrzdns`
//! cargo xtask store-binaries <ordner>   Programm für linux/amd64 und linux/arm64, gzip (Umbrel-Paket)
//! ```
//!
//! Die Tailwind-Eingabe steht in `ui/tailwind.rs`, das Dockerfile in `xtask/src/docker.rs`;
//! `ui/tailwind.css` und `Dockerfile` entstehen erst beim Bauen und sind nicht im Repository.

mod docker;
#[path = "../../ui/tailwind.rs"]
mod tailwind;
mod ui;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "\
Aufruf: cargo xtask <aufgabe>

  ui                        Oberfläche bauen (ui/ → ui/dist/public), danach `cargo build`
  serve [dx-optionen]       Oberfläche mit Hot Reload (dx serve, http://localhost:8080)
  dockerfile                Dockerfile ausgeben, z. B. `cargo xtask dockerfile > Dockerfile`
  docker [optionen]         docker buildx build mit diesem Dockerfile, z. B. `-t nrzdns`
  store-binaries <ordner>   Programm für linux/amd64 und linux/arm64, gzip (Umbrel-Paket)";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let task = args.next();
    let rest: Vec<String> = args.collect();
    let result = match (task.as_deref(), rest.as_slice()) {
        (Some("ui"), []) => ui::bundle(),
        (Some("serve"), _) => ui::serve(&rest),
        (Some("dockerfile"), []) => {
            print!("{}", docker::dockerfile());
            Ok(())
        }
        (Some("docker"), _) => docker::build(&rest),
        (Some("store-binaries"), [dest]) => docker::store_binaries(Path::new(dest)),
        (Some("help" | "-h" | "--help"), _) => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Hauptordner des Repositorys (xtask/ liegt direkt darin).
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask liegt im Hauptordner")
        .to_path_buf()
}

/// Befehl ausführen; Fehler, wenn er nicht startet oder nicht mit 0 endet.
fn run(cmd: &mut Command) -> Result {
    let name = cmd.get_program().to_string_lossy().into_owned();
    let status = cmd
        .status()
        .map_err(|e| format!("{name} lässt sich nicht starten: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{name} ist fehlgeschlagen ({status})").into())
    }
}
