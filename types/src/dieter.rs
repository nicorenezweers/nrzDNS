//! Dieter: KI-Assistent für das Netzwerk (OpenRouter, Grok/xAI oder Claude CLI). Er darf –
//! wenn erlaubt – alles konfigurieren, was die Oberfläche kann, und springt automatisch
//! ein, wenn die Überwachung ein Problem findet.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DieterProvider {
    #[default]
    Openrouter,
    Xai,
    ClaudeCli,
}

/// Einstellungen (ohne Schlüssel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterSettings {
    pub provider: DieterProvider,
    /// Modell je Anbieter (leer = Vorgabe).
    pub openrouter_model: String,
    pub xai_model: String,
    pub claude_model: String,
    /// Dieter darf Einstellungen ändern (sonst nur lesen und vorschlagen).
    pub allow_changes: bool,
    /// Überwachung: bei Problemen automatisch einschalten.
    pub auto_watch: bool,
    /// Alle so viele Minuten prüfen (5–240).
    pub watch_minutes: u32,
    /// Bei automatischen Einsätzen selbst beheben (sonst nur untersuchen und berichten).
    pub auto_fix: bool,
}

impl Default for DieterSettings {
    fn default() -> Self {
        Self {
            provider: DieterProvider::Openrouter,
            openrouter_model: String::new(),
            xai_model: String::new(),
            claude_model: String::new(),
            allow_changes: true,
            auto_watch: true,
            watch_minutes: 10,
            auto_fix: true,
        }
    }
}

/// `PUT /dieter/settings` – leere Schlüssel = behalten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterSettingsInput {
    #[serde(flatten)]
    pub settings: DieterSettings,
    pub openrouter_key: String,
    pub xai_key: String,
    /// Claude: API-Schlüssel (sk-ant-api…) oder Token aus `claude setup-token` (sk-ant-oat…).
    pub claude_token: String,
    /// Diese Schlüssel löschen: `openrouter`, `xai`, `claude`.
    pub clear: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterConversation {
    pub id: i64,
    pub title: String,
    /// Von der Überwachung gestartet.
    pub automatic: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// Läuft gerade.
    pub running: bool,
}

/// Eine Nachricht für die Anzeige.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterMessage {
    pub id: i64,
    /// `user`, `assistant`, `action` (Werkzeug), `error`.
    pub role: String,
    pub text: String,
    /// Bei `action`: Werkzeug und Kurzform der Argumente.
    pub tool: String,
    pub detail: String,
    pub created_at: i64,
}

/// Ein Problem, das die Überwachung gefunden hat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterIncident {
    pub key: String,
    pub text: String,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Noch vorhanden bei der letzten Prüfung.
    pub active: bool,
    /// Einsatz von Dieter dazu (0 = keiner).
    pub conversation_id: i64,
}

/// `GET /dieter`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterStatus {
    pub settings: DieterSettings,
    pub openrouter_key_set: bool,
    pub xai_key_set: bool,
    pub claude_token_set: bool,
    /// Bereit (Schlüssel für den gewählten Anbieter vorhanden, Claude CLI installiert).
    pub ready: bool,
    pub ready_detail: String,
    pub claude_version: String,
    pub conversations: Vec<DieterConversation>,
    pub incidents: Vec<DieterIncident>,
    /// Letzte Prüfung der Überwachung (Unix-Sekunden).
    pub last_watch: i64,
}

/// `GET /dieter/conversations/<id>`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterThread {
    pub conversation: DieterConversation,
    pub messages: Vec<DieterMessage>,
}

/// `POST /dieter/conversations` bzw. `POST /dieter/conversations/<id>/messages`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DieterSendInput {
    pub text: String,
    /// Seite, auf der der Benutzer gerade ist (nur für Dieter, nicht angezeigt).
    pub context: String,
}
