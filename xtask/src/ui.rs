//! Oberfläche (Dioxus, `ui/`): Tailwind-Eingabe schreiben und die Dioxus-CLI (`dx`, 0.7) aufrufen.
//! Braucht rustup mit dem Ziel `wasm32-unknown-unknown` und
//! `cargo install dioxus-cli --version 0.7.10 --locked`.

use crate::{root, run, tailwind, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, io};

const DX_MISSING: &str =
    "Dioxus-CLI fehlt: `cargo install dioxus-cli --version 0.7.10 --locked` (und `rustup target add wasm32-unknown-unknown`)";

/// Release-Build nach `ui/dist/public`; `build.rs` bettet ihn beim nächsten `cargo build` ein.
///
/// `dx bundle` räumt seinen Zwischenordner (`target/dx/…/public`) nicht auf und kopiert alles
/// daraus mit – darum den vorher leeren und in einen frischen Ordner bauen, sonst landen alte
/// WASM-Dateien im Programm.
pub fn bundle() -> Result {
    let ui = root().join("ui");
    write_tailwind_input(&ui)?;
    remove_dir(&ui.join("target/dx/nrzdns-ui/release/web/public"))?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let out = ui.join(format!("target/ui-bundle-{stamp}"));
    run(dx()?
        .current_dir(&ui)
        .args(["bundle", "--web", "--release", "--out-dir"])
        .arg(&out))?;

    let public = out.join("public");
    if !public.join("index.html").is_file() {
        return Err(format!("{}/index.html fehlt", public.display()).into());
    }
    let dist = ui.join("dist/public");
    remove_dir(&dist)?;
    fs::create_dir_all(ui.join("dist"))?;
    fs::rename(&public, &dist)?;
    remove_dir(&out)?;
    println!(
        "Oberfläche gebaut: ui/dist/public ({:.1} MiB) – jetzt `cargo build`, damit sie ins Programm kommt",
        dir_size(&dist)? as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}

/// Entwickeln mit Hot Reload; API, Schriften und Übersetzungen kommen vom laufenden Server
/// (Proxy in `ui/Dioxus.toml`). Weitere Optionen gehen unverändert an `dx serve`.
pub fn serve(args: &[String]) -> Result {
    let ui = root().join("ui");
    write_tailwind_input(&ui)?;
    run(dx()?.current_dir(&ui).arg("serve").args(args))
}

/// `ui/tailwind.css` aus `ui/tailwind.rs` schreiben – nur wenn sich etwas ändert, denn `dx serve`
/// beobachtet die Datei. `dx` findet sie von selbst und übersetzt sie vor dem Build.
fn write_tailwind_input(ui: &Path) -> Result {
    let path = ui.join("tailwind.css");
    if fs::read_to_string(&path).ok().as_deref() != Some(tailwind::INPUT) {
        fs::write(&path, tailwind::INPUT)?;
    }
    Ok(())
}

/// Die Dioxus-CLI. `~/.cargo/bin` und die stabile rustup-Toolchain kommen im PATH nach vorn,
/// sonst gewinnt leicht ein anderes `dx` (Deno) oder ein Rust ohne wasm32-Ziel (Homebrew).
fn dx() -> Result<Command> {
    let home = env::var_os("HOME").map(PathBuf::from);
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".cargo")));
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".rustup")));

    let mut front = Vec::new();
    if let Some(dir) = cargo_home.map(|c| c.join("bin")).filter(|d| d.is_dir()) {
        front.push(dir);
    }
    if let Some(dir) = rustup_home.and_then(|r| stable_toolchain_bin(&r)) {
        front.push(dir);
    }
    let rest = env::var_os("PATH").unwrap_or_default();
    let path = env::join_paths(front.into_iter().chain(env::split_paths(&rest)))?;

    let name = format!("dx{}", env::consts::EXE_SUFFIX);
    let exe = env::split_paths(&path)
        .map(|dir| dir.join(&name))
        .find(|p| p.is_file())
        .ok_or(DX_MISSING)?;
    let version = Command::new(&exe)
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if !version.starts_with("dioxus") {
        return Err(format!(
            "{} ist nicht die Dioxus-CLI ({version}) – {DX_MISSING}",
            exe.display()
        )
        .into());
    }
    if !version.starts_with("dioxus 0.7.") {
        eprintln!("Warnung: {version} – gebaut wird mit dioxus-cli 0.7.10");
    }
    let mut cmd = Command::new(exe);
    cmd.env("PATH", path);
    Ok(cmd)
}

/// `<RUSTUP_HOME>/toolchains/stable-<ziel>/bin`, falls vorhanden.
fn stable_toolchain_bin(rustup_home: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(rustup_home.join("toolchains"))
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("stable-"))
        .map(|e| e.path().join("bin"))
        .filter(|d| d.is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

fn remove_dir(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        total += if meta.is_dir() {
            dir_size(&entry.path())?
        } else {
            meta.len()
        };
    }
    Ok(total)
}
