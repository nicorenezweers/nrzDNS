//! Netzwerk-Tools (Ping, Ports, HTTP-Check) und Geräte im Netzwerk.

use crate::auth::{AdminUser, CurrentUser};
use crate::error::AppResult;
use crate::services::tools;
use nrzdns_engine::Engine;
use nrzdns_types::{
    Device, DeviceNameInput, HttpCheckInput, HttpCheckResult, PingInput, PingResult, PortsInput,
    PortsResult,
};
use rocket::serde::json::Json;
use rocket::{get, post, put, routes, Route, State};
use sqlx::SqlitePool;

pub fn routes() -> Vec<Route> {
    routes![ping, ports, http, devices, rename]
}

#[post("/tools/ping", data = "<body>")]
async fn ping(
    _user: CurrentUser,
    body: Json<PingInput>,
    engine: &State<Engine>,
) -> AppResult<Json<PingResult>> {
    Ok(Json(tools::ping(engine, &body.host, body.count).await?))
}

#[post("/tools/ports", data = "<body>")]
async fn ports(
    _user: CurrentUser,
    body: Json<PortsInput>,
    engine: &State<Engine>,
) -> AppResult<Json<PortsResult>> {
    Ok(Json(tools::ports(engine, &body.host, &body.ports).await?))
}

#[post("/tools/http", data = "<body>")]
async fn http(_user: CurrentUser, body: Json<HttpCheckInput>) -> AppResult<Json<HttpCheckResult>> {
    Ok(Json(tools::http_check(&body.url).await?))
}

#[get("/devices?<days>")]
async fn devices(
    _user: CurrentUser,
    days: Option<u32>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Vec<Device>>> {
    Ok(Json(tools::devices(pool, days.unwrap_or(7)).await?))
}

#[put("/devices/<ip>", data = "<body>")]
async fn rename(
    _admin: AdminUser,
    ip: &str,
    body: Json<DeviceNameInput>,
    pool: &State<SqlitePool>,
) -> AppResult<Json<Device>> {
    Ok(Json(tools::set_device_name(pool, ip, &body.name).await?))
}
