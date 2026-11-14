//! Zugriffsprotokoll speichern und auswerten (Monitor).

use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::proxy::ProxyState;
use crate::services::{integrations, proxy};
use nrzdns_types::{AccessBucket, AccessClient, AccessCount, AccessEntry, AccessHost, AccessStats};
use sqlx::SqlitePool;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// Puffer des Proxys in die Datenbank schreiben.
pub async fn flush(pool: &SqlitePool, state: &ProxyState) -> AppResult<usize> {
    let entries = state.access().take();
    if entries.is_empty() {
        return Ok(0);
    }
    let mut tx = pool.begin().await?;
    for e in &entries {
        sqlx::query(
            "INSERT INTO access_log (at_ms, host, method, path, status, bytes, duration_ms, client,
                                     source, country, user_agent, referer, kind)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(e.at_ms)
        .bind(&e.host)
        .bind(&e.method)
        .bind(&e.path)
        .bind(i64::from(e.status))
        .bind(i64::try_from(e.bytes).unwrap_or(i64::MAX))
        .bind(i64::from(e.duration_ms))
        .bind(&e.client)
        .bind(&e.source)
        .bind(&e.country)
        .bind(&e.user_agent)
        .bind(&e.referer)
        .bind(&e.kind)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(entries.len())
}

/// Ältere Einträge löschen (`days` aus den Proxy-Einstellungen).
pub async fn purge(pool: &SqlitePool) -> AppResult<u64> {
    let days = proxy::settings(pool).await?.access_log_days;
    let keep = i64::from(if days == 0 { 1 } else { days });
    let cutoff = (now() - keep * 86_400) * 1000;
    Ok(sqlx::query("DELETE FROM access_log WHERE at_ms < ?")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected())
}

pub async fn clear(pool: &SqlitePool) -> AppResult<()> {
    sqlx::query("DELETE FROM access_log").execute(pool).await?;
    Ok(())
}

fn period_secs(period: &str) -> AppResult<(i64, i64)> {
    // (Zeitraum, Länge eines Balkens)
    match period {
        "" | "24h" => Ok((86_400, 3_600)),
        "7d" => Ok((7 * 86_400, 6 * 3_600)),
        "30d" => Ok((30 * 86_400, 86_400)),
        _ => Err(AppError::bad("Zeitraum: 24h, 7d oder 30d.")),
    }
}

/// Bekannte Namen: eigene Gerätenamen und NetBird-Geräte.
async fn names(pool: &SqlitePool) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = crate::services::docker::cached_names()
        .into_iter()
        .map(|(ip, n)| (ip, format!("Container {n}")))
        .collect();
    for (ip, name) in integrations::netbird_peer_names(pool).await {
        map.insert(ip.to_string(), name);
    }
    let own: Vec<(String, String)> = sqlx::query_as("SELECT ip, name FROM device_names")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for (ip, name) in own {
        map.insert(ip, name);
    }
    map
}

/// Browser oder Bot aus dem User-Agent.
pub fn agent_family(ua: &str) -> &'static str {
    let l = ua.to_lowercase();
    if l.is_empty() {
        return "ohne Angabe";
    }
    const BOTS: &[(&str, &str)] = &[
        ("googlebot", "Googlebot"),
        ("bingbot", "Bingbot"),
        ("applebot", "Applebot"),
        ("gptbot", "GPTBot"),
        ("claudebot", "ClaudeBot"),
        ("ahrefs", "Ahrefs"),
        ("semrush", "Semrush"),
        ("uptimerobot", "UptimeRobot"),
        ("censys", "Censys"),
        ("shodan", "Shodan"),
        ("zgrab", "Scanner (zgrab)"),
        ("masscan", "Scanner (masscan)"),
        ("nmap", "Scanner (Nmap)"),
        ("curl/", "curl"),
        ("wget/", "Wget"),
        ("python-requests", "Python"),
        ("go-http-client", "Go"),
    ];
    if let Some((_, n)) = BOTS.iter().find(|(k, _)| l.contains(k)) {
        return n;
    }
    if l.contains("bot") || l.contains("crawler") || l.contains("spider") {
        return "andere Bots";
    }
    if l.contains("edg/") {
        "Edge"
    } else if l.contains("opr/") || l.contains("opera") {
        "Opera"
    } else if l.contains("firefox/") {
        "Firefox"
    } else if l.contains("chrome/") || l.contains("crios/") {
        "Chrome"
    } else if l.contains("safari/") {
        "Safari"
    } else if l.contains("jellyfin")
        || l.contains("okhttp")
        || l.contains("dalvik")
        || l.contains("cfnetwork")
    {
        "Apps"
    } else {
        "andere"
    }
}

fn host_filter(host: Option<&str>) -> (String, Vec<String>) {
    match host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) => (" AND host = ?".into(), vec![h.to_lowercase()]),
        None => (String::new(), Vec::new()),
    }
}

fn counts(rows: Vec<(String, i64)>) -> Vec<AccessCount> {
    rows.into_iter()
        .map(|(key, count)| AccessCount {
            key,
            count: count.max(0) as u64,
        })
        .collect()
}

pub async fn stats(
    pool: &SqlitePool,
    state: &ProxyState,
    period: &str,
    host: Option<&str>,
) -> AppResult<AccessStats> {
    flush(pool, state).await?;
    let (span, bucket) = period_secs(period)?;
    let since = (now() - span) * 1000;
    let (hf, hb) = host_filter(host);
    macro_rules! bind_all {
        ($query:expr) => {{
            let mut q = $query.bind(since);
            for b in &hb {
                q = q.bind(b.clone());
            }
            q
        }};
    }

    let (requests, visitors, bytes, errors, blocked): (i64, i64, i64, i64, i64) = bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT count(*), count(DISTINCT client), coalesce(sum(bytes), 0), coalesce(sum(status >= 500), 0),
                coalesce(sum(kind = 'blocked'), 0)
         FROM access_log WHERE at_ms >= ?{hf}"
    ))))
    .fetch_one(pool)
    .await?;

    let buckets: Vec<(i64, i64, i64)> = bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT (at_ms / 1000 / {bucket}) * {bucket} AS b, count(*), count(DISTINCT client)
         FROM access_log WHERE at_ms >= ?{hf} GROUP BY b ORDER BY b"
    ))))
    .fetch_all(pool)
    .await?;
    let by_start: BTreeMap<i64, (i64, i64)> =
        buckets.into_iter().map(|(b, r, v)| (b, (r, v))).collect();
    let first = ((now() - span) / bucket + 1) * bucket;
    let timeline = (0..span / bucket)
        .map(|i| {
            let start = first + i * bucket;
            let (r, v) = by_start.get(&start).copied().unwrap_or((0, 0));
            AccessBucket {
                start,
                requests: r as u64,
                visitors: v as u64,
            }
        })
        .collect();

    let public: Vec<String> = sqlx::query_scalar("SELECT host FROM proxy_hosts WHERE public = 1")
        .fetch_all(pool)
        .await?;
    let hosts_rows: Vec<(String, i64, i64, i64, i64, i64)> = bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT host, count(*), count(DISTINCT client), coalesce(sum(bytes), 0), coalesce(sum(status >= 500), 0), max(at_ms)
         FROM access_log WHERE at_ms >= ?{hf} GROUP BY host ORDER BY count(*) DESC LIMIT 100"
    ))))
    .fetch_all(pool)
    .await?;
    let hosts = hosts_rows
        .into_iter()
        .map(|(h, r, v, b, e, l)| AccessHost {
            public: public.contains(&h),
            host: h,
            requests: r as u64,
            visitors: v as u64,
            bytes: b.max(0) as u64,
            errors: e as u64,
            last_at_ms: l,
        })
        .collect();

    let group = |col: &str, limit: u32| {
        format!("SELECT {col}, count(*) FROM access_log WHERE at_ms >= ?{hf} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}")
    };
    let sources = counts(
        bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(group("source", 10))))
            .fetch_all(pool)
            .await?,
    );
    let paths = counts(
        bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(group(
            "host || path",
            20
        ))))
        .fetch_all(pool)
        .await?,
    );
    let countries = counts(
        bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(group("country", 20))))
            .fetch_all(pool)
            .await?,
    )
    .into_iter()
    .filter(|c| !c.key.is_empty())
    .collect();
    let statuses = counts(
        bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(group(
            "CAST(status AS TEXT)",
            20
        ))))
        .fetch_all(pool)
        .await?,
    );
    let ua_rows: Vec<(String, i64)> = bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(group(
        "user_agent",
        500
    ))))
    .fetch_all(pool)
    .await?;
    let mut fam: BTreeMap<&str, u64> = BTreeMap::new();
    for (ua, n) in ua_rows {
        *fam.entry(agent_family(&ua)).or_default() += n.max(0) as u64;
    }
    let mut agents: Vec<AccessCount> = fam
        .into_iter()
        .map(|(k, c)| AccessCount {
            key: k.into(),
            count: c,
        })
        .collect();
    agents.sort_by_key(|a| std::cmp::Reverse(a.count));

    let names = names(pool).await;
    let client_rows: Vec<(String, String, String, i64, i64)> =
        bind_all!(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT client, max(source), max(country), count(*), max(at_ms)
         FROM access_log WHERE at_ms >= ?{hf} GROUP BY client ORDER BY count(*) DESC LIMIT 30"
        ))))
        .fetch_all(pool)
        .await?;
    let clients = client_rows
        .into_iter()
        .map(|(c, s, co, r, l)| AccessClient {
            name: names.get(&c).cloned().unwrap_or_default(),
            client: c,
            source: s,
            country: co,
            requests: r as u64,
            last_at_ms: l,
        })
        .collect();

    Ok(AccessStats {
        period: if period.is_empty() {
            "24h".into()
        } else {
            period.into()
        },
        requests: requests as u64,
        visitors: visitors as u64,
        bytes: bytes.max(0) as u64,
        errors: errors as u64,
        blocked: blocked as u64,
        timeline,
        hosts,
        sources,
        paths,
        clients,
        countries,
        statuses,
        agents,
    })
}

type LogRow = (
    i64,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// Neueste Zugriffe (Live-Ansicht).
pub async fn log(
    pool: &SqlitePool,
    state: &ProxyState,
    host: Option<&str>,
    limit: u32,
    before_ms: Option<i64>,
) -> AppResult<Vec<AccessEntry>> {
    flush(pool, state).await?;
    let limit = limit.clamp(1, 500);
    let before = before_ms.unwrap_or(i64::MAX);
    let (hf, hb) = host_filter(host);
    let mut q = sqlx::query_as::<_, LogRow>(sqlx::AssertSqlSafe(format!(
        "SELECT at_ms, host, method, path, status, bytes, duration_ms, client, source, country, user_agent, referer, kind
         FROM access_log WHERE at_ms < ?{hf} ORDER BY at_ms DESC, id DESC LIMIT {limit}"
    )))
    .bind(before);
    for b in &hb {
        q = q.bind(b.clone());
    }
    let rows = q.fetch_all(pool).await?;
    let names = names(pool).await;
    Ok(rows
        .into_iter()
        .map(
            |(
                at_ms,
                host,
                method,
                path,
                status,
                bytes,
                dur,
                client,
                source,
                country,
                ua,
                referer,
                kind,
            )| AccessEntry {
                client_name: names.get(&client).cloned().unwrap_or_default(),
                at_ms,
                host,
                method,
                path,
                status: u16::try_from(status).unwrap_or(0),
                bytes: bytes.max(0) as u64,
                duration_ms: u32::try_from(dur).unwrap_or(0),
                client,
                source,
                country,
                user_agent: ua,
                referer,
                kind,
            },
        )
        .collect())
}

/// Docker-Host (`host.docker.internal`) auflösen – Verbindungen von dort kamen über das Gerät.
pub async fn resolve_gateway(name: Option<&str>) -> Option<IpAddr> {
    let name = name?;
    tokio::net::lookup_host((name, 80))
        .await
        .ok()?
        .map(|a| a.ip())
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents() {
        assert_eq!(
            agent_family(
                "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15"
            ),
            "Safari"
        );
        assert_eq!(
            agent_family("Mozilla/5.0 Chrome/131.0 Safari/537.36"),
            "Chrome"
        );
        assert_eq!(
            agent_family("Mozilla/5.0 Chrome/131.0 Safari/537.36 Edg/131.0"),
            "Edge"
        );
        assert_eq!(
            agent_family("Mozilla/5.0 (compatible; Googlebot/2.1)"),
            "Googlebot"
        );
        assert_eq!(agent_family("curl/8.4.0"), "curl");
        assert_eq!(agent_family(""), "ohne Angabe");
    }
}
