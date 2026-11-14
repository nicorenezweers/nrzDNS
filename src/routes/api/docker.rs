//! Docker beobachten (nur lesend).

use crate::auth::CurrentUser;
use crate::config::Config;
use crate::error::AppResult;
use crate::services::docker;
use nrzdns_types::DockerOverview;
use rocket::serde::json::Json;
use rocket::{get, routes, Route, State};
use serde_json::Value;

pub fn routes() -> Vec<Route> {
    routes![overview, logs, inspect]
}

#[get("/docker")]
async fn overview(_u: CurrentUser, config: &State<Config>) -> Json<DockerOverview> {
    Json(docker::overview(config).await)
}

#[get("/docker/containers/<name>/logs?<tail>")]
async fn logs(
    _u: CurrentUser,
    name: &str,
    tail: Option<u32>,
    config: &State<Config>,
) -> AppResult<Json<Vec<String>>> {
    Ok(Json(docker::logs(config, name, tail.unwrap_or(200)).await?))
}

#[get("/docker/containers/<name>", rank = 2)]
async fn inspect(_u: CurrentUser, name: &str, config: &State<Config>) -> AppResult<Json<Value>> {
    Ok(Json(docker::inspect(config, name).await?))
}
