//! Seiten des Proxys: die Sperrseite von nrzNetwork (auf Zeit freischalten, dauerhafte Ausnahme
//! beantragen) und kurze Meldungen (404, 502 …). Deutsch, Englisch nach `Accept-Language`.
//! Ohne JavaScript – alles läuft über Formulare an `/.nrznetwork/…` auf dem gesperrten Namen.

use super::{foreign_origin, read_form, unlock, ProxyState, ACTION_PREFIX};
use crate::services::unlocks;
use hyper::header::{self, HeaderMap};
use hyper::{Body, Request, Response, StatusCode};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    De,
    En,
}

impl Lang {
    pub fn from_headers(h: &HeaderMap) -> Lang {
        let accept = h
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if accept.starts_with("de") || accept.is_empty() {
            Lang::De
        } else if accept.starts_with("en") {
            Lang::En
        } else if accept.contains("de") {
            Lang::De
        } else {
            Lang::En
        }
    }

    fn t(self, de: &'static str, en: &'static str) -> &'static str {
        match self {
            Lang::De => de,
            Lang::En => en,
        }
    }
}

pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const STYLE: &str = "\
*{box-sizing:border-box}body{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;\
background:#0f0f11;color:#e4e4e7;display:grid;place-items:center;min-height:100vh;margin:0;padding:1.5rem}\
main{width:100%;max-width:34rem;background:#18181b;border:1px solid #27272a;border-radius:1rem;padding:2rem;\
box-shadow:0 10px 40px rgba(0,0,0,.4)}\
.badge{display:inline-flex;align-items:center;gap:.4rem;font-size:.75rem;font-weight:600;letter-spacing:.04em;\
text-transform:uppercase;color:#a1a1aa}.dot{width:.5rem;height:.5rem;border-radius:50%;background:#ef4444}\
.ok .dot{background:#22c55e}h1{font-size:1.35rem;line-height:1.3;margin:.75rem 0 .5rem}\
p{color:#a1a1aa;margin:.4rem 0;line-height:1.5}.domain{font-family:ui-monospace,Menlo,monospace;color:#f4f4f5;\
background:#27272a;border-radius:.4rem;padding:.15rem .45rem;word-break:break-all}\
.why{font-size:.8rem;color:#71717a;margin-top:.75rem}hr{border:0;border-top:1px solid #27272a;margin:1.5rem 0}\
h2{font-size:.95rem;margin:0 0 .6rem}.row{display:flex;flex-wrap:wrap;gap:.5rem}\
button{font:inherit;cursor:pointer;border-radius:.5rem;padding:.55rem .9rem;border:1px solid #3f3f46;\
background:#27272a;color:#f4f4f5;font-size:.875rem}button:hover{background:#3f3f46}\
button.primary{background:#f4f4f5;color:#18181b;border-color:#f4f4f5}button.primary:hover{background:#d4d4d8}\
textarea{width:100%;min-height:4.5rem;font:inherit;font-size:.875rem;color:#f4f4f5;background:#0f0f11;\
border:1px solid #3f3f46;border-radius:.5rem;padding:.6rem;margin-bottom:.6rem;resize:vertical}\
.note{font-size:.8rem;color:#71717a}.foot{margin-top:1.5rem;font-size:.75rem;color:#52525b}";

fn html(
    lang: Lang,
    status: StatusCode,
    title: &str,
    body: &str,
    refresh: Option<&str>,
) -> Response<Body> {
    let refresh = refresh
        .map(|url| {
            format!(
                "<meta http-equiv=\"refresh\" content=\"2;url={}\">",
                escape(url)
            )
        })
        .unwrap_or_default();
    let html = format!(
        "<!doctype html><html lang=\"{l}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\">{refresh}<title>{title}</title><style>{STYLE}</style></head>\
         <body><main>{body}<p class=\"foot\">nrzNetwork</p></main></body></html>",
        l = if lang == Lang::De { "de" } else { "en" },
        title = escape(title),
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
        )
        .body(Body::from(html))
        .unwrap_or_default()
}

/// Kurze Meldung (Text darf schon HTML mit maskierten Werten enthalten). Deutsch; englische
/// Browser bekommen dieselbe Meldung mit englischem Titel.
pub fn message(lang: Lang, status: StatusCode, text: &str) -> Response<Body> {
    let body = format!(
        "<span class=\"badge\"><span class=\"dot\"></span>{} {}</span><h1>{}</h1><p>{text}</p>",
        status.as_u16(),
        lang.t("Reverse Proxy", "Reverse proxy"),
        status.canonical_reason().unwrap_or(""),
    );
    html(
        lang,
        status,
        status.canonical_reason().unwrap_or("nrzNetwork"),
        &body,
        None,
    )
}

/// Nur ein Pfad auf diesem Host (gegen offene Weiterleitungen).
fn safe_back(back: Option<&String>) -> String {
    match back {
        Some(b)
            if b.starts_with('/') && !b.starts_with("//") && !b.contains(['\r', '\n', '\\']) =>
        {
            b.clone()
        }
        _ => "/".into(),
    }
}

fn minutes_label(lang: Lang, m: u32) -> String {
    match (lang, m) {
        (Lang::De, m) if m % 60 == 0 && m >= 60 => {
            let h = m / 60;
            if h == 1 {
                "1 Stunde".into()
            } else {
                format!("{h} Stunden")
            }
        }
        (Lang::De, m) => format!("{m} Minuten"),
        (Lang::En, m) if m % 60 == 0 && m >= 60 => {
            let h = m / 60;
            if h == 1 {
                "1 hour".into()
            } else {
                format!("{h} hours")
            }
        }
        (Lang::En, m) => format!("{m} minutes"),
    }
}

/// Anfrage an eine gesperrte Domain: Seite zeigen oder Aktion ausführen.
pub async fn handle_blocked(
    state: &ProxyState,
    req: Request<Body>,
    peer: SocketAddr,
    host: &str,
    raw_host: &str,
    matches: Vec<String>,
    lang: Lang,
) -> Response<Body> {
    let settings = state.settings();
    let client = peer.ip().to_canonical();
    let path = req.uri().path().to_string();
    let full = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_string();

    if let Some(action) = path.strip_prefix(ACTION_PREFIX) {
        if foreign_origin(&req, raw_host) {
            return message(
                lang,
                StatusCode::FORBIDDEN,
                lang.t(
                    "Anfrage von einer fremden Seite.",
                    "Request from a foreign site.",
                ),
            );
        }
        let action = action.to_string();
        let Some(form) = read_form(req).await else {
            return redirect_to_page(raw_host);
        };
        if !state.allow_action(client) {
            return message(
                lang,
                StatusCode::TOO_MANY_REQUESTS,
                lang.t(
                    "Zu viele Versuche – bitte in ein paar Minuten nochmals.",
                    "Too many attempts – please try again in a few minutes.",
                ),
            );
        }
        let back = safe_back(form.get("back"));
        match action.as_str() {
            "unlock" if settings.allow_unlock => {
                let minutes = form
                    .get("minutes")
                    .and_then(|m| m.parse::<u32>().ok())
                    .filter(|m| settings.unlock_minutes.contains(m));
                let Some(minutes) = minutes else {
                    return message(
                        lang,
                        StatusCode::BAD_REQUEST,
                        lang.t(
                            "Diesen Zeitraum gibt es nicht.",
                            "This period is not available.",
                        ),
                    );
                };
                if !unlock(state, host, minutes, client).await {
                    return message(
                        lang,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        lang.t("Freischalten hat nicht geklappt.", "Unlocking failed."),
                    );
                }
                let url = format!("http://{raw_host}{back}");
                let body = format!(
                    "<span class=\"badge ok\"><span class=\"dot\"></span>nrzNetwork</span>\
                     <h1>{title}</h1><p><span class=\"domain\">{d}</span> {text}</p>\
                     <p class=\"note\">{wait} <a href=\"{u}\" style=\"color:#e4e4e7\">{go}</a></p>",
                    title = lang.t("Freigeschaltet", "Unlocked"),
                    d = escape(host),
                    text = match lang {
                        Lang::De =>
                            format!("ist für {} freigeschaltet.", minutes_label(lang, minutes)),
                        Lang::En => format!("is unlocked for {}.", minutes_label(lang, minutes)),
                    },
                    wait = lang.t("Du wirst gleich weitergeleitet …", "Redirecting …"),
                    u = escape(&url),
                    go = lang.t("Jetzt öffnen", "Open now"),
                );
                html(
                    lang,
                    StatusCode::OK,
                    lang.t("Freigeschaltet", "Unlocked"),
                    &body,
                    Some(&url),
                )
            }
            "request" if settings.allow_requests => {
                let reason = form.get("reason").map(String::as_str).unwrap_or("");
                match unlocks::create_request(&state.0.ctx.pool, host, reason, &client.to_string())
                    .await
                {
                    Ok(_) => {
                        tracing::info!(domain = %host, client = %client, "Ausnahme beantragt");
                        let body = format!(
                            "<span class=\"badge ok\"><span class=\"dot\"></span>nrzNetwork</span>\
                             <h1>{title}</h1><p>{text}</p><p><a href=\"{back}\" style=\"color:#e4e4e7\">{again}</a></p>",
                            title = lang.t("Anfrage gesendet", "Request sent"),
                            text = match lang {
                                Lang::De => format!("Der Admin entscheidet, ob <span class=\"domain\">{}</span> dauerhaft freigegeben wird.", escape(host)),
                                Lang::En => format!("The admin decides whether <span class=\"domain\">{}</span> is allowed permanently.", escape(host)),
                            },
                            back = escape(&back),
                            again = lang.t("Zurück", "Back"),
                        );
                        html(
                            lang,
                            StatusCode::OK,
                            lang.t("Anfrage gesendet", "Request sent"),
                            &body,
                            None,
                        )
                    }
                    Err(e) => {
                        tracing::warn!("Antrag: {e}");
                        message(
                            lang,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            lang.t(
                                "Die Anfrage konnte nicht gespeichert werden.",
                                "The request could not be saved.",
                            ),
                        )
                    }
                }
            }
            _ => message(
                lang,
                StatusCode::FORBIDDEN,
                lang.t("Das ist hier nicht erlaubt.", "This is not allowed here."),
            ),
        }
    } else {
        let pending = unlocks::pending_for(&state.0.ctx.pool, host)
            .await
            .ok()
            .flatten()
            .is_some();
        blocked_page(lang, host, &matches, &settings, pending, &full)
    }
}

fn redirect_to_page(raw_host: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, format!("http://{raw_host}/"))
        .body(Body::empty())
        .unwrap_or_default()
}

fn blocked_page(
    lang: Lang,
    host: &str,
    matches: &[String],
    settings: &nrzdns_types::ProxySettings,
    pending: bool,
    back: &str,
) -> Response<Body> {
    let why = matches
        .iter()
        .take(3)
        .map(|m| escape(m))
        .collect::<Vec<_>>()
        .join(" · ");
    let back = escape(back);
    let mut body = format!(
        "<span class=\"badge\"><span class=\"dot\"></span>{badge}</span>\
         <h1>{title}</h1><p><span class=\"domain\">{d}</span></p><p>{text}</p>",
        badge = lang.t("Gesperrt", "Blocked"),
        title = lang.t("Diese Seite wurde durch nrzNetwork gesperrt", "This site was blocked by nrzNetwork"),
        d = escape(host),
        text = lang.t(
            "Sie steht auf einer Sperrliste dieses Netzwerks – meist wegen Werbung, Tracking oder Schadsoftware.",
            "It is on a blocklist of this network – usually because of ads, tracking or malware."
        ),
    );
    if !why.is_empty() {
        body.push_str(&format!(
            "<p class=\"why\">{}: {why}</p>",
            lang.t("Grund", "Reason")
        ));
    }
    if settings.allow_unlock && !settings.unlock_minutes.is_empty() {
        body.push_str(&format!(
            "<hr><h2>{}</h2><form method=\"post\" action=\"/.nrznetwork/unlock\" class=\"row\">\
             <input type=\"hidden\" name=\"back\" value=\"{back}\">",
            lang.t("Für eine Weile freischalten", "Unlock for a while")
        ));
        for (i, m) in settings.unlock_minutes.iter().enumerate() {
            body.push_str(&format!(
                "<button{} name=\"minutes\" value=\"{m}\">{}</button>",
                if i == 0 { " class=\"primary\"" } else { "" },
                minutes_label(lang, *m)
            ));
        }
        body.push_str(&format!(
            "</form><p class=\"note\">{}</p>",
            lang.t(
                "Gilt für alle Geräte im Netzwerk und endet von selbst.",
                "Applies to all devices on the network and ends by itself."
            )
        ));
    }
    if settings.allow_requests {
        body.push_str(&format!(
            "<hr><h2>{}</h2>",
            lang.t("Dauerhaft freigeben lassen", "Ask for permanent access")
        ));
        if pending {
            body.push_str(&format!(
                "<p class=\"note\">{}</p>",
                lang.t("Für diese Seite wartet schon eine Anfrage auf den Admin. Du kannst eine Begründung ergänzen.", "A request for this site is already waiting for the admin. You can add a reason.")
            ));
        }
        body.push_str(&format!(
            "<form method=\"post\" action=\"/.nrznetwork/request\">\
             <input type=\"hidden\" name=\"back\" value=\"{back}\">\
             <textarea name=\"reason\" maxlength=\"500\" placeholder=\"{ph}\"></textarea>\
             <button>{btn}</button></form>",
            ph = lang.t(
                "Warum brauchst du diese Seite? (optional)",
                "Why do you need this site? (optional)"
            ),
            btn = lang.t("Freigabe beantragen", "Request access"),
        ));
    }
    html(
        lang,
        StatusCode::FORBIDDEN,
        lang.t("Gesperrt – nrzNetwork", "Blocked – nrzNetwork"),
        &body,
        None,
    )
}
