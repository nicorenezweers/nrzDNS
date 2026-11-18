//! Routen: `api` ist die REST-API unter `/api/v1` (auch die Oberfläche nutzt nur sie),
//! `doh` ist DNS über HTTPS unter `/dns-query`, `mcp` der MCP-Server unter `/mcp`, `spa` liefert die Oberfläche
//! (Dioxus/WebAssembly), `assets` Schrift, Icons und Übersetzungen, `catchers` beantwortet
//! Fehler als JSON oder HTML.

pub mod api;
pub mod assets;
pub mod catchers;
pub mod doh;
pub mod mcp;
pub mod spa;
